"""
analyzer.py

TokenAnalyzer performs a multi-source risk audit of an ERC-20 token deployed
on Base Mainnet (chain id 8453), combining:

  1. Direct on-chain RPC calls (via RPCManager) for ground-truth contract
     metadata, ownership state, pausability probing, and LP-burn verification.
  2. GoPlus Security "Token Security" API for honeypot / tax / mint /
     blacklist / ownership / holder-concentration intelligence.
  3. DexScreener API for liquidity (USD), trading pairs, volume and price.

Results are merged into a single RiskReport with a 0-100 Risk Score and a
classification: SAFE / CAUTION / HIGH_RISK / CRITICAL_HONEYPOT.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx
from web3 import AsyncWeb3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from rpc_manager import RPCManager, RPCConnectionError

logger = logging.getLogger("agentrisk.analyzer")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

BASE_CHAIN_ID_STR = "8453"
GOPLUS_TOKEN_SECURITY_URL = "https://api.gopluslabs.io/api/v1/token_security/{chain_id}"
DEXSCREENER_TOKEN_URL = "https://api.dexscreener.com/latest/dex/tokens/{address}"
HTTP_TIMEOUT_SECONDS = 12

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000000000000000"
NULL_ADDRESS = "0x0000000000000000000000000000000000000000"
DEAD_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "name",
     "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol",
     "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals",
     "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "account", "type": "address"}],
     "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}],
     "type": "function"},
]

OWNABLE_ABI = [
    {"constant": True, "inputs": [], "name": "owner",
     "outputs": [{"name": "", "type": "address"}], "type": "function"},
]

PAUSABLE_ABI = [
    {"constant": True, "inputs": [], "name": "paused",
     "outputs": [{"name": "", "type": "bool"}], "type": "function"},
]


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL_HONEYPOT = "CRITICAL_HONEYPOT"


def classify(score: int) -> RiskLevel:
    if score <= 15:
        return RiskLevel.SAFE
    if score <= 45:
        return RiskLevel.CAUTION
    if score <= 75:
        return RiskLevel.HIGH_RISK
    return RiskLevel.CRITICAL_HONEYPOT


@dataclass
class RiskFinding:
    code: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    message: str
    weight: int


@dataclass
class RiskReport:
    address: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: int = field(default_factory=lambda: int(time.time()))
    chain: str = "base"
    chain_id: int = 8453
    name: Optional[str] = None
    symbol: Optional[str] = None
    decimals: Optional[int] = None
    total_supply: Optional[str] = None
    is_contract: bool = False

    is_honeypot: Optional[bool] = None
    buy_tax_pct: Optional[float] = None
    sell_tax_pct: Optional[float] = None
    hidden_tax_flag: bool = False

    is_open_source: Optional[bool] = None
    is_proxy: Optional[bool] = None
    owner_address: Optional[str] = None
    ownership_renounced: Optional[bool] = None
    can_take_back_ownership: Optional[bool] = None
    hidden_owner: Optional[bool] = None
    owner_change_balance: Optional[bool] = None

    is_mintable: Optional[bool] = None
    is_blacklisted_function: Optional[bool] = None
    is_whitelisted_function: Optional[bool] = None
    transfer_pausable: Optional[bool] = None
    trading_cooldown: Optional[bool] = None
    self_destruct: Optional[bool] = None
    slippage_modifiable: Optional[bool] = None

    liquidity_usd: Optional[float] = None
    main_pair_address: Optional[str] = None
    main_dex: Optional[str] = None
    lp_locked_or_burned: Optional[bool] = None
    lp_burned_pct: Optional[float] = None
    lp_source: Optional[str] = None
    pairs_found: int = 0
    price_usd: Optional[float] = None
    volume_24h_usd: Optional[float] = None

    holder_count: Optional[int] = None
    top10_holder_pct: Optional[float] = None
    creator_pct: Optional[float] = None
    creator_address: Optional[str] = None

    data_sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[RiskFinding] = field(default_factory=list)

    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.CAUTION
    verdict: str = ""
    confidence: str = "high"
    cached: bool = False
    sell_simulation: Optional[dict] = None


KNOWN_BRANDS = [
    "apple", "google", "meta", "nvidia", "tesla", "amazon", "microsoft",
    "netflix", "alphabet", "openai", "coinbase", "binance", "visa",
    "mastercard", "paypal", "disney", "samsung", "intel", "amd",
]


def _check_brand_impersonation(name: str, symbol: str) -> str | None:
    text = f"{name} {symbol}".lower()
    for brand in KNOWN_BRANDS:
        if brand in text:
            return brand
    return None


async def _check_deployer_freshness(rpc_manager, deployer_address: str) -> int | None:
    """Returns the transaction count (nonce) of the deployer wallet, or None if unavailable."""
    if not deployer_address:
        return None
    try:
        async def _op(w3):
            checksum = w3.to_checksum_address(deployer_address)
            return await w3.eth.get_transaction_count(checksum)
        return await rpc_manager.call_with_fallback(_op)
    except Exception:
        return None


QUOTER_V2_ADDRESS = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a"
WETH_ADDRESS = "0x4200000000000000000000000000000000000006"
V3_FEE_TIERS = [(100, "0.01%"), (500, "0.05%"), (3000, "0.3%"), (10000, "1%")]


async def _simulate_sell(rpc_manager, token_address: str) -> dict | None:
    """Universal sell simulation: tries getReserves() for V2-style pools,
    then slot0() for V3/Slipstream-style pools, using the real quote token
    and DEX reported by DexScreener instead of assuming WETH/Uniswap."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://api.dexscreener.com/latest/dex/tokens/{token_address}")
            data = resp.json()
            pairs = data.get("pairs", [])
            if not pairs:
                return None
            pairs.sort(key=lambda p: p.get("liquidity", {}).get("usd", 0) or 0, reverse=True)
            best_pair = pairs[0]
            pair_address = best_pair.get("pairAddress", "")
            quote_symbol = best_pair.get("quoteToken", {}).get("symbol")
            dex_id = best_pair.get("dexId")

        if len(pair_address) != 42:
            return {"sellable": None, "reason": f"unsupported pool format ({dex_id})"}

        async def try_methods(w3):
            pair = w3.to_checksum_address(pair_address)
            try:
                token0_result = await w3.eth.call({"to": pair, "data": "0x0dfe1681"})
                token0 = "0x" + token0_result[-20:].hex()
            except Exception:
                return {"sellable": None, "reason": "could not read pool token0"}
            is_token0 = token0.lower() == token_address.lower()

            try:
                result = await w3.eth.call({"to": pair, "data": "0x0902f1ac"})
                reserve0 = int.from_bytes(result[0:32], "big")
                reserve1 = int.from_bytes(result[32:64], "big")
                token_reserve = reserve0 if is_token0 else reserve1
                quote_reserve = reserve1 if is_token0 else reserve0
                if token_reserve == 0:
                    raise ValueError("zero reserve")
                amount_in = 1000 * 10**18
                amount_out = (amount_in * quote_reserve) // (token_reserve + amount_in)
                return {"sellable": True, "method": "getReserves", "quote_token": quote_symbol, "amount_out": amount_out / 1e18, "dex": dex_id}
            except Exception:
                pass

            try:
                result = await w3.eth.call({"to": pair, "data": "0x3850c7bd"})
                sqrt_price_x96 = int.from_bytes(result[0:32], "big")
                if sqrt_price_x96 == 0:
                    raise ValueError("zero price")
                return {"sellable": True, "method": "slot0", "quote_token": quote_symbol, "dex": dex_id}
            except Exception:
                pass

            return {"sellable": False, "method": "none worked", "dex": dex_id}

        return await rpc_manager.call_with_fallback(try_methods)
    except Exception:
        return None


class TokenAnalyzer:
    """
    Runs a full multi-source risk audit for a given ERC-20 token address on
    Base Mainnet. Instantiate once per request (cheap) and call `analyze()`.
    """

    def __init__(self, rpc_manager: RPCManager, http_client: Optional[httpx.AsyncClient] = None):
        self.rpc_manager = rpc_manager
        self._external_client = http_client
        self._owns_client = http_client is None
        self._cache: dict[str, tuple[float, "RiskReport"]] = {}
        self._cache_ttl_seconds = 30

    async def _get_client(self) -> httpx.AsyncClient:
        if self._external_client is not None:
            return self._external_client
        self._external_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)
        return self._external_client

    async def aclose(self) -> None:
        if self._owns_client and self._external_client is not None:
            await self._external_client.aclose()
            self._external_client = None

    # ------------------------------------------------------------------ #
    # Address validation
    # ------------------------------------------------------------------ #

    def validate_address(self, address: str) -> str:
        """Returns a checksummed address or raises ValueError if malformed."""
        if not address or not isinstance(address, str):
            raise ValueError("Token address must be a non-empty string.")
        candidate = address.strip()
        if not AsyncWeb3.is_address(candidate):
            raise ValueError(f"'{address}' is not a valid EVM address.")
        return AsyncWeb3.to_checksum_address(candidate)

    # ------------------------------------------------------------------ #
    # On-chain (direct RPC) checks
    # ------------------------------------------------------------------ #

    async def _fetch_onchain_metadata(self, address: str, report: RiskReport) -> None:
        try:
            code = await self.rpc_manager.get_code(address)
        except RPCConnectionError as exc:
            report.warnings.append(f"RPC unreachable while fetching bytecode: {exc}")
            return

        report.is_contract = code is not None and len(code) > 0
        if not report.is_contract:
            report.warnings.append(
                "Address has no deployed bytecode (EOA or not-yet-deployed contract)."
            )
            return

        async def _read_erc20(w3: AsyncWeb3) -> dict[str, Any]:
            contract = w3.eth.contract(address=address, abi=ERC20_ABI)
            out: dict[str, Any] = {}
            for field_name in ("name", "symbol", "decimals", "totalSupply"):
                try:
                    fn = getattr(contract.functions, field_name)
                    out[field_name] = await fn().call()
                except (ContractLogicError, BadFunctionCallOutput, Exception) as exc:  # noqa: BLE001
                    logger.debug("ERC20 field '%s' unavailable for %s: %s", field_name, address, exc)
                    out[field_name] = None
            return out

        try:
            erc20_data = await self.rpc_manager.call_with_fallback(_read_erc20)
            report.name = erc20_data.get("name")
            report.symbol = erc20_data.get("symbol")
            report.decimals = erc20_data.get("decimals")
            total_supply = erc20_data.get("totalSupply")
            report.total_supply = str(total_supply) if total_supply is not None else None
        except RPCConnectionError as exc:
            report.warnings.append(f"RPC unreachable while reading ERC-20 metadata: {exc}")

        # Ownership: read owner() directly on-chain as a ground-truth cross-check
        async def _read_owner(w3: AsyncWeb3) -> Optional[str]:
            contract = w3.eth.contract(address=address, abi=OWNABLE_ABI)
            try:
                return await contract.functions.owner().call()
            except (ContractLogicError, BadFunctionCallOutput, Exception):  # noqa: BLE001
                return None

        try:
            onchain_owner = await self.rpc_manager.call_with_fallback(_read_owner)
            if onchain_owner is not None:
                report.owner_address = onchain_owner
                report.ownership_renounced = onchain_owner.lower() in DEAD_ADDRESSES
        except RPCConnectionError as exc:
            report.warnings.append(f"RPC unreachable while reading owner(): {exc}")

        # Pausability: probe paused() directly; presence of a callable paused()
        # strongly implies a Pausable/blacklist-style trading-halt mechanism.
        async def _read_paused(w3: AsyncWeb3) -> Optional[bool]:
            contract = w3.eth.contract(address=address, abi=PAUSABLE_ABI)
            try:
                return await contract.functions.paused().call()
            except (ContractLogicError, BadFunctionCallOutput, Exception):  # noqa: BLE001
                return None

        try:
            paused_state = await self.rpc_manager.call_with_fallback(_read_paused)
            if paused_state is not None:
                report.transfer_pausable = True
                if paused_state:
                    report.findings.append(
                        RiskFinding(
                            code="TRADING_CURRENTLY_PAUSED",
                            severity="critical",
                            message="Contract exposes paused() and trading is CURRENTLY paused on-chain.",
                            weight=40,
                        )
                    )
        except RPCConnectionError as exc:
            report.warnings.append(f"RPC unreachable while probing paused(): {exc}")

        report.data_sources.append("base_rpc")

    async def _check_lp_burn_onchain(self, report: RiskReport) -> None:
        """
        If a main liquidity pair address is known (from DexScreener), read the
        pair's own ERC-20 (LP token) totalSupply and the balance held at the
        dead/zero address directly on-chain. A high burned percentage is
        strong, unspoofable evidence that liquidity cannot be rugged by
        withdrawal of that specific pool's LP tokens.
        """
        if not report.main_pair_address:
            return

        pair_address = report.main_pair_address

        async def _read_lp(w3: AsyncWeb3) -> dict[str, Any]:
            lp_contract = w3.eth.contract(address=pair_address, abi=ERC20_ABI)
            total_supply = await lp_contract.functions.totalSupply().call()
            dead_balance = await lp_contract.functions.balanceOf(
                w3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
            ).call()
            zero_balance = await lp_contract.functions.balanceOf(
                w3.to_checksum_address(NULL_ADDRESS)
            ).call()
            return {
                "total_supply": total_supply,
                "dead_balance": dead_balance,
                "zero_balance": zero_balance,
            }

        try:
            lp_data = await self.rpc_manager.call_with_fallback(_read_lp)
            total_supply = lp_data["total_supply"]
            if total_supply and total_supply > 0:
                burned = lp_data["dead_balance"] + lp_data["zero_balance"]
                burned_pct = round((burned / total_supply) * 100, 4)
                report.lp_burned_pct = burned_pct
                report.lp_locked_or_burned = burned_pct >= 90.0
                report.lp_source = "onchain_lp_burn_check"
                report.data_sources.append("base_rpc_lp_check")
        except RPCConnectionError as exc:
            report.warnings.append(f"RPC unreachable while checking LP burn: {exc}")
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(f"LP burn check failed (pair may not be a standard LP token): {exc}")

    # ------------------------------------------------------------------ #
    # GoPlus Security API
    # ------------------------------------------------------------------ #

    async def _fetch_goplus(self, address: str, report: RiskReport) -> None:
        client = await self._get_client()
        url = GOPLUS_TOKEN_SECURITY_URL.format(chain_id=BASE_CHAIN_ID_STR)
        params = {"contract_addresses": address.lower()}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            report.warnings.append(f"GoPlus Security API unreachable: {exc}")
            return
        except ValueError as exc:
            report.warnings.append(f"GoPlus Security API returned invalid JSON: {exc}")
            return

        if payload.get("code") != 1:
            report.warnings.append(
                f"GoPlus Security API error: {payload.get('message', 'unknown error')}"
            )
            return

        result = payload.get("result") or {}
        token_data = result.get(address.lower())
        if not token_data:
            report.warnings.append("GoPlus Security API returned no data for this address.")
            return

        def _flag(key: str) -> Optional[bool]:
            val = token_data.get(key)
            if val is None:
                return None
            return str(val) == "1"

        def _float(key: str) -> Optional[float]:
            val = token_data.get(key)
            try:
                return float(val) if val not in (None, "") else None
            except (TypeError, ValueError):
                return None

        report.is_honeypot = _flag("is_honeypot")
        report.buy_tax_pct = (_float("buy_tax") or 0.0) * 100
        report.sell_tax_pct = (_float("sell_tax") or 0.0) * 100
        report.is_open_source = _flag("is_open_source")
        report.is_proxy = _flag("is_proxy")
        report.is_mintable = _flag("is_mintable")
        report.is_blacklisted_function = _flag("is_blacklisted")
        report.is_whitelisted_function = _flag("is_whitelisted")
        report.trading_cooldown = _flag("trading_cooldown")
        report.self_destruct = _flag("selfdestruct")
        report.slippage_modifiable = _flag("slippage_modifiable")
        report.can_take_back_ownership = _flag("can_take_back_ownership")
        report.hidden_owner = _flag("hidden_owner")
        report.owner_change_balance = _flag("owner_change_balance")

        cannot_sell_all = _flag("cannot_sell_all")
        cannot_buy = _flag("cannot_buy")
        if cannot_sell_all or cannot_buy:
            report.is_honeypot = True

        transfer_pausable_goplus = _flag("transfer_pausable")
        if transfer_pausable_goplus is not None:
            report.transfer_pausable = report.transfer_pausable or transfer_pausable_goplus

        owner_address = token_data.get("owner_address")
        if owner_address:
            report.owner_address = owner_address
            report.ownership_renounced = owner_address.lower() in DEAD_ADDRESSES or owner_address == ""

        try:
            holder_count = token_data.get("holder_count")
            report.holder_count = int(holder_count) if holder_count not in (None, "") else None
        except (TypeError, ValueError):
            pass

        holders = token_data.get("holders") or []
        try:
            excluded_tags = {"burn", "black hole", "dead"}
            top10 = holders[:10]
            top10_pct = 0.0
            has_pct = False
            for h in top10:
                tag = str(h.get("tag") or "").lower()
                if any(t in tag for t in excluded_tags):
                    continue
                pct = h.get("percent")
                if pct is not None:
                    top10_pct += float(pct)
                    has_pct = True
            if has_pct:
                report.top10_holder_pct = round(top10_pct * 100, 4)
        except (TypeError, ValueError):
            pass

        creator_pct = _float("creator_percent")
        if creator_pct is not None:
            report.creator_pct = round(creator_pct * 100, 4)

        creator_addr = token_data.get("creator_address")
        if creator_addr:
            report.creator_address = creator_addr

        lp_holders = token_data.get("lp_holders") or []
        if lp_holders and report.lp_locked_or_burned is None:
            try:
                locked_or_burned_pct = 0.0
                for lp in lp_holders:
                    is_locked = str(lp.get("is_locked")) == "1"
                    tag = str(lp.get("tag") or "").lower()
                    pct = float(lp.get("percent") or 0.0)
                    if is_locked or "burn" in tag or "black hole" in tag or "dead" in tag:
                        locked_or_burned_pct += pct
                report.lp_burned_pct = report.lp_burned_pct or round(locked_or_burned_pct * 100, 4)
                report.lp_locked_or_burned = locked_or_burned_pct >= 0.9
                report.lp_source = report.lp_source or "goplus_lp_holders"
            except (TypeError, ValueError):
                pass

        other_risks = token_data.get("other_potential_risks")
        if other_risks:
            report.warnings.append(f"GoPlus flagged additional risk notes: {other_risks}")

        if str(token_data.get("fake_token", "0")) == "1":
            report.warnings.append("GoPlus flags this contract as impersonating a known token (fake_token).")

        if str(token_data.get("honeypot_with_same_creator", "0")) not in ("0", "", None):
            report.warnings.append(
                "GoPlus reports the creator of this token has deployed honeypots previously."
            )

        report.data_sources.append("goplus_security")

    # ------------------------------------------------------------------ #
    # DexScreener API
    # ------------------------------------------------------------------ #

    async def _fetch_dexscreener(self, address: str, report: RiskReport) -> None:
        client = await self._get_client()
        url = DEXSCREENER_TOKEN_URL.format(address=address)
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            report.warnings.append(f"DexScreener API unreachable: {exc}")
            return
        except ValueError as exc:
            report.warnings.append(f"DexScreener API returned invalid JSON: {exc}")
            return

        pairs = payload.get("pairs") or []
        base_pairs = [p for p in pairs if str(p.get("chainId", "")).lower() == "base"]
        report.pairs_found = len(base_pairs)

        if not base_pairs:
            report.warnings.append("No liquidity pairs found for this token on Base via DexScreener.")
            report.data_sources.append("dexscreener")
            return

        def _liquidity_usd(pair: dict) -> float:
            liq = pair.get("liquidity") or {}
            try:
                return float(liq.get("usd") or 0.0)
            except (TypeError, ValueError):
                return 0.0

        best_pair = max(base_pairs, key=_liquidity_usd)
        report.liquidity_usd = _liquidity_usd(best_pair)
        report.main_pair_address = best_pair.get("pairAddress")
        report.main_dex = best_pair.get("dexId")

        try:
            report.price_usd = float(best_pair.get("priceUsd")) if best_pair.get("priceUsd") else None
        except (TypeError, ValueError):
            report.price_usd = None

        volume = best_pair.get("volume") or {}
        try:
            report.volume_24h_usd = float(volume.get("h24")) if volume.get("h24") is not None else None
        except (TypeError, ValueError):
            report.volume_24h_usd = None

        if report.main_pair_address:
            try:
                report.main_pair_address = AsyncWeb3.to_checksum_address(report.main_pair_address)
            except ValueError:
                report.main_pair_address = None

        report.data_sources.append("dexscreener")

    # ------------------------------------------------------------------ #
    # Risk scoring
    # ------------------------------------------------------------------ #

    def _score(self, report: RiskReport) -> None:
        score = 0
        findings = report.findings  # may already contain the "trading paused" finding

        if report.is_honeypot:
            findings.append(RiskFinding(
                code="HONEYPOT_DETECTED", severity="critical",
                message="Token cannot be sold (honeypot) or sells are blocked.",
                weight=60,
            ))
            score += 60

        max_tax = max([t for t in [report.buy_tax_pct, report.sell_tax_pct] if t is not None] or [0.0])
        if max_tax > 0:
            if max_tax > 25:
                findings.append(RiskFinding(
                    code="EXTREME_TAX", severity="critical",
                    message=f"Buy/sell tax is extremely high ({max_tax:.1f}%).",
                    weight=35,
                ))
                score += 35
            elif max_tax > 10:
                report.hidden_tax_flag = True
                findings.append(RiskFinding(
                    code="HIGH_TAX", severity="high",
                    message=f"Buy/sell tax exceeds 10% ({max_tax:.1f}%).",
                    weight=20,
                ))
                score += 20
            elif max_tax > 5:
                findings.append(RiskFinding(
                    code="ELEVATED_TAX", severity="medium",
                    message=f"Buy/sell tax is elevated ({max_tax:.1f}%).",
                    weight=8,
                ))
                score += 8

        if report.slippage_modifiable:
            findings.append(RiskFinding(
                code="SLIPPAGE_MODIFIABLE", severity="high",
                message="Owner can dynamically change buy/sell tax after deployment.",
                weight=15,
            ))
            score += 15

        if report.ownership_renounced is False:
            if report.is_mintable:
                findings.append(RiskFinding(
                    code="ACTIVE_OWNER_PLUS_MINT", severity="high",
                    message="Ownership is NOT renounced and the contract exposes a mint function.",
                    weight=25,
                ))
                score += 25
            else:
                findings.append(RiskFinding(
                    code="OWNERSHIP_NOT_RENOUNCED", severity="medium",
                    message="Ownership has not been renounced; owner retains privileged control.",
                    weight=10,
                ))
                score += 10
        elif report.is_mintable:
            findings.append(RiskFinding(
                code="MINTABLE", severity="medium",
                message="Contract exposes a mint function (supply can be increased).",
                weight=12,
            ))
            score += 12

        if report.hidden_owner:
            findings.append(RiskFinding(
                code="HIDDEN_OWNER", severity="high",
                message="Contract conceals a privileged/hidden owner address.",
                weight=18,
            ))
            score += 18

        if report.can_take_back_ownership:
            findings.append(RiskFinding(
                code="OWNERSHIP_RECLAIMABLE", severity="high",
                message="Renounced ownership can reportedly be reclaimed by the deployer.",
                weight=18,
            ))
            score += 18

        if report.owner_change_balance:
            findings.append(RiskFinding(
                code="OWNER_CAN_CHANGE_BALANCE", severity="critical",
                message="Owner can directly modify arbitrary account balances.",
                weight=30,
            ))
            score += 30

        if report.is_blacklisted_function:
            findings.append(RiskFinding(
                code="BLACKLIST_FUNCTION", severity="high",
                message="Contract can blacklist individual wallets from trading.",
                weight=15,
            ))
            score += 15

        if report.transfer_pausable:
            already_critical = any(f.code == "TRADING_CURRENTLY_PAUSED" for f in findings)
            if not already_critical:
                findings.append(RiskFinding(
                    code="TRADING_PAUSABLE", severity="medium",
                    message="Owner can pause all token transfers at will.",
                    weight=12,
                ))
                score += 12

        if report.trading_cooldown:
            findings.append(RiskFinding(
                code="TRADING_COOLDOWN", severity="low",
                message="Contract enforces a trading cooldown between transactions.",
                weight=5,
            ))
            score += 5

        if report.self_destruct:
            findings.append(RiskFinding(
                code="SELFDESTRUCT_PRESENT", severity="high",
                message="Contract can self-destruct, potentially wiping token state.",
                weight=15,
            ))
            score += 15

        if report.is_open_source is False:
            findings.append(RiskFinding(
                code="NOT_VERIFIED", severity="medium",
                message="Contract source code is not verified/open-source.",
                weight=10,
            ))
            score += 10

        if report.is_proxy:
            findings.append(RiskFinding(
                code="UPGRADEABLE_PROXY", severity="medium",
                message="Contract is an upgradeable proxy; logic can change post-deployment.",
                weight=10,
            ))
            score += 10

        if report.pairs_found == 0:
            findings.append(RiskFinding(
                code="NO_LIQUIDITY_FOUND", severity="high",
                message="No tradeable liquidity pool found on Base.",
                weight=20,
            ))
            score += 20
        else:
            if report.liquidity_usd is not None and report.liquidity_usd < 1000:
                findings.append(RiskFinding(
                    code="LOW_LIQUIDITY", severity="medium",
                    message=f"Main pool liquidity is very low (${report.liquidity_usd:,.2f}).",
                    weight=12,
                ))
                score += 12
            elif report.liquidity_usd is not None and report.liquidity_usd < 10000:
                findings.append(RiskFinding(
                    code="MODERATE_LIQUIDITY", severity="low",
                    message=f"Main pool liquidity is modest (${report.liquidity_usd:,.2f}).",
                    weight=5,
                ))
                score += 5

            if report.lp_locked_or_burned is False:
                findings.append(RiskFinding(
                    code="LP_NOT_LOCKED", severity="high",
                    message="Liquidity pool tokens are not burned or locked — rug-pull risk.",
                    weight=20,
                ))
                score += 20
            elif report.lp_locked_or_burned is None:
                findings.append(RiskFinding(
                    code="LP_LOCK_STATUS_UNKNOWN", severity="low",
                    message="Could not verify whether LP tokens are locked or burned.",
                    weight=5,
                ))
                score += 5

        if report.top10_holder_pct is not None:
            if report.top10_holder_pct > 80:
                findings.append(RiskFinding(
                    code="EXTREME_HOLDER_CONCENTRATION", severity="critical",
                    message=f"Top 10 holders control {report.top10_holder_pct:.1f}% of supply.",
                    weight=25,
                ))
                score += 25
            elif report.top10_holder_pct > 50:
                findings.append(RiskFinding(
                    code="HIGH_HOLDER_CONCENTRATION", severity="high",
                    message=f"Top 10 holders control {report.top10_holder_pct:.1f}% of supply.",
                    weight=15,
                ))
                score += 15
            elif report.top10_holder_pct > 30:
                findings.append(RiskFinding(
                    code="MODERATE_HOLDER_CONCENTRATION", severity="medium",
                    message=f"Top 10 holders control {report.top10_holder_pct:.1f}% of supply.",
                    weight=8,
                ))
                score += 8

        if not report.is_contract:
            findings.append(RiskFinding(
                code="NOT_A_CONTRACT", severity="critical",
                message="Address has no deployed bytecode on Base.",
                weight=100,
            ))
            score = 100

        score = max(0, min(100, score))

        if report.is_honeypot or (report.transfer_pausable and any(
            f.code == "TRADING_CURRENTLY_PAUSED" for f in findings
        )):
            score = max(score, 80)

        report.risk_score = score
        report.risk_level = classify(score)

    # ------------------------------------------------------------------ #
    # Public entry points
    # ------------------------------------------------------------------ #

    def _build_verdict(self, report: RiskReport) -> str:
        level = report.risk_level.value
        reasons = [f.message.rstrip(".") for f in report.findings[:2]]
        reason_text = "; ".join(reasons) if reasons else "no significant issues found"

        if level == "CRITICAL_HONEYPOT":
            prefix = "DO NOT TRADE"
        elif level == "HIGH_RISK":
            prefix = "HIGH RISK — avoid unless you understand the tradeoffs"
        elif level == "CAUTION":
            prefix = "PROCEED WITH CAUTION"
        else:
            prefix = "LOOKS SAFE"

        return f"{prefix}. {reason_text}."

    async def analyze(self, address: str, deep: bool = True) -> RiskReport:
        checksum_address = self.validate_address(address)

        cache_key = f"{checksum_address}:{deep}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            cached_at, cached_report = cached
            if (time.time() - cached_at) < self._cache_ttl_seconds:
                cached_report.cached = True
                return cached_report

        report = RiskReport(address=checksum_address)

        onchain_meta_task = asyncio.create_task(self._fetch_onchain_metadata(checksum_address, report))
        goplus_task = asyncio.create_task(self._fetch_goplus(checksum_address, report))
        dexscreener_task = asyncio.create_task(self._fetch_dexscreener(checksum_address, report))

        results = await asyncio.gather(
            onchain_meta_task, goplus_task, dexscreener_task, return_exceptions=True
        )
        for res in results:
            if isinstance(res, Exception):
                report.warnings.append(f"Unexpected analyzer error: {res}")

        if deep and report.is_contract:
            try:
                lp_status_before = report.lp_locked_or_burned
                await self._check_lp_burn_onchain(report)
                lp_status_after = report.lp_locked_or_burned
                if (
                    lp_status_before is not None
                    and lp_status_after is not None
                    and lp_status_before != lp_status_after
                ):
                    report.findings.append(
                        RiskFinding(
                            code="DATA_SOURCE_DISAGREEMENT",
                            severity="high",
                            message=f"Data sources disagree on LP lock status: third-party API says {lp_status_before}, direct on-chain check says {lp_status_after}. Treat with caution.",
                            weight=20,
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                report.warnings.append(f"LP burn verification failed: {exc}")

            sim_result = await _simulate_sell(self.rpc_manager, report.address)
            if sim_result is not None:
                report.sell_simulation = sim_result
                if sim_result.get("sellable") is False and not report.is_honeypot:
                    report.findings.append(
                        RiskFinding(
                            code="SELL_SIMULATION_FAILED",
                            severity="critical",
                            message="Live sell simulation failed via all available on-chain methods — this token may not be sellable right now, even though static checks did not flag it as a honeypot.",
                            weight=40,
                        )
                    )
                    report.risk_score = min(100, report.risk_score + 40)
                    if report.risk_score >= 60:
                        report.risk_level = RiskLevel.HIGH_RISK
                    elif report.risk_score >= 30:
                        report.risk_level = RiskLevel.CAUTION
                    report.verdict = self._build_verdict(report)

        matched_brand = _check_brand_impersonation(report.name or "", report.symbol or "")
        if matched_brand:
            report.findings.append(
                RiskFinding(
                    code="POSSIBLE_BRAND_IMPERSONATION",
                    severity="medium",
                    message=f"Token name/symbol resembles '{matched_brand.title()}'. This may be an unofficial or impersonating token — verify the issuer before trusting the brand name.",
                    weight=10,
                )
            )

        if report.creator_address:
            deployer_nonce = await _check_deployer_freshness(self.rpc_manager, report.creator_address)
            if deployer_nonce is not None and deployer_nonce <= 3:
                report.findings.append(
                    RiskFinding(
                        code="FRESH_DEPLOYER_WALLET",
                        severity="medium",
                        message=f"Deployer wallet has only {deployer_nonce} prior transaction(s) — this may be a newly created wallet used for a one-off token launch.",
                        weight=10,
                    )
                )

        self._score(report)
        report.verdict = self._build_verdict(report)

        missing_key_data = report.creator_address is None or report.lp_locked_or_burned is None
        report.confidence = "low" if missing_key_data else "high"

        self._cache[cache_key] = (time.time(), report)
        return report

    async def quick_scan(self, address: str) -> RiskReport:
        return await self.analyze(address, deep=False)

    async def deep_scan(self, address: str) -> RiskReport:
        return await self.analyze(address, deep=True)

