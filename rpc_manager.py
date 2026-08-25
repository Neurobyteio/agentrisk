"""
rpc_manager.py

Asynchronous RPC connection manager for Base Mainnet (Chain ID 8453).
Provides automatic failover from PRIMARY_BASE_RPC to FALLBACK_BASE_RPC
whenever the primary endpoint is unreachable, times out, or returns
an invalid chain id.

Environment variables (.env):
    PRIMARY_BASE_RPC   - primary Base Mainnet RPC HTTP(S) endpoint
    FALLBACK_BASE_RPC  - fallback Base Mainnet RPC HTTP(S) endpoint
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Awaitable, Callable, Optional

from dotenv import load_dotenv
from web3 import AsyncWeb3
from web3 import AsyncHTTPProvider

load_dotenv()

logger = logging.getLogger("agentrisk.rpc_manager")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

BASE_CHAIN_ID = 8453
RPC_TIMEOUT_SECONDS = 10
RPC_CALL_ATTEMPTS_PER_ENDPOINT = 1


class RPCConnectionError(Exception):
    """Raised when neither the primary nor the fallback RPC endpoint is usable."""


class RPCManager:
    """
    Wraps two AsyncWeb3 instances (primary / fallback) pointed at Base Mainnet
    and transparently retries any RPC operation against the fallback endpoint
    if the primary endpoint fails, times out, or is on the wrong chain.
    """

    def __init__(
        self,
        primary_url: Optional[str] = None,
        fallback_url: Optional[str] = None,
    ) -> None:
        self.primary_url: Optional[str] = primary_url or os.getenv("PRIMARY_BASE_RPC")
        self.fallback_url: Optional[str] = fallback_url or os.getenv("FALLBACK_BASE_RPC")

        if not self.primary_url:
            raise RuntimeError(
                "PRIMARY_BASE_RPC is not set. Define it in your .env file, e.g.\n"
                "PRIMARY_BASE_RPC=https://mainnet.base.org"
            )
        if not self.fallback_url:
            logger.warning(
                "FALLBACK_BASE_RPC is not set — automatic failover is disabled."
            )

        self._primary_w3: Optional[AsyncWeb3] = None
        self._fallback_w3: Optional[AsyncWeb3] = None
        self._lock = asyncio.Lock()
        self.active_endpoint: str = "primary"
        self._initialized = False

    def _build_web3(self, url: str) -> AsyncWeb3:
        provider = AsyncHTTPProvider(
            url,
            request_kwargs={"timeout": RPC_TIMEOUT_SECONDS},
        )
        return AsyncWeb3(provider)

    async def initialize(self) -> None:
        async with self._lock:
            if self._initialized:
                return
            self._primary_w3 = self._build_web3(self.primary_url)
            if self.fallback_url:
                self._fallback_w3 = self._build_web3(self.fallback_url)
            self._initialized = True
            logger.info("RPCManager initialized (primary + %s fallback)",
                        "with" if self._fallback_w3 else "no")

    async def _is_endpoint_healthy(self, w3: AsyncWeb3) -> bool:
        try:
            connected = await asyncio.wait_for(
                w3.is_connected(), timeout=RPC_TIMEOUT_SECONDS
            )
            if not connected:
                return False
            chain_id = await asyncio.wait_for(
                w3.eth.chain_id, timeout=RPC_TIMEOUT_SECONDS
            )
            if chain_id != BASE_CHAIN_ID:
                logger.error(
                    "RPC endpoint reports chain_id=%s, expected Base (%s)",
                    chain_id,
                    BASE_CHAIN_ID,
                )
                return False
            return True
        except Exception as exc:  # noqa: BLE001 - we deliberately swallow to try fallback
            logger.warning("RPC health probe failed: %s", exc)
            return False

    async def get_web3(self, prefer: Optional[str] = None) -> AsyncWeb3:
        """
        Returns a healthy AsyncWeb3 instance. Tries the primary endpoint first
        (unless `prefer='fallback'`), transparently switching to the fallback
        endpoint if the primary is unhealthy.
        """
        if not self._initialized:
            await self.initialize()

        order = ["primary", "fallback"] if prefer != "fallback" else ["fallback", "primary"]

        for endpoint in order:
            w3 = self._primary_w3 if endpoint == "primary" else self._fallback_w3
            if w3 is None:
                continue
            if await self._is_endpoint_healthy(w3):
                if self.active_endpoint != endpoint:
                    logger.info("Active Base RPC endpoint switched to '%s'", endpoint)
                self.active_endpoint = endpoint
                return w3

        raise RPCConnectionError(
            "Both PRIMARY_BASE_RPC and FALLBACK_BASE_RPC are unreachable or "
            "not serving Base Mainnet (chain id 8453)."
        )

    async def call_with_fallback(
        self, func: Callable[[AsyncWeb3], Awaitable[Any]]
    ) -> Any:
        """
        Executes `func(w3)` against the currently active endpoint. If it raises,
        automatically retries once against the other endpoint before giving up.
        """
        errors: list[str] = []

        try:
            w3 = await self.get_web3(prefer=self.active_endpoint)
            return await func(w3)
        except RPCConnectionError:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{self.active_endpoint}: {exc}")
            logger.warning("RPC call failed on '%s': %s", self.active_endpoint, exc)

        other = "fallback" if self.active_endpoint == "primary" else "primary"
        try:
            w3 = await self.get_web3(prefer=other)
            result = await func(w3)
            return result
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{other}: {exc}")
            logger.error("RPC call failed on fallback attempt '%s': %s", other, exc)

        raise RPCConnectionError(
            "All Base RPC endpoints failed while executing request: " + "; ".join(errors)
        )

    async def get_current_block(self) -> int:
        async def _op(w3: AsyncWeb3) -> int:
            return await w3.eth.block_number

        return await self.call_with_fallback(_op)

    async def get_code(self, address: str) -> bytes:
        async def _op(w3: AsyncWeb3) -> bytes:
            checksum = w3.to_checksum_address(address)
            return await w3.eth.get_code(checksum)

        return await self.call_with_fallback(_op)

    async def health_check(self) -> dict:
        try:
            block_number = await self.get_current_block()
            return {
                "connected": True,
                "active_endpoint": self.active_endpoint,
                "chain_id": BASE_CHAIN_ID,
                "current_block": block_number,
                "error": None,
            }
        except RPCConnectionError as exc:
            return {
                "connected": False,
                "active_endpoint": None,
                "chain_id": BASE_CHAIN_ID,
                "current_block": None,
                "error": str(exc),
            }


# Module-level singleton shared across the FastAPI app
rpc_manager = RPCManager()
