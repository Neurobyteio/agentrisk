from __future__ import annotations
import tracker
import os
import json
import time
import logging
from typing import Optional

if not os.getenv("PRIMARY_BASE_RPC"):
    os.environ["PRIMARY_BASE_RPC"] = "https://mainnet.base.org"

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from analyzer import TokenAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agentrisk")

import mcp_server

app = FastAPI(
    title="AgentRisk M2M Security API",
    description="Autonomous AI Agent for Real-time Risk Scoring. Accepts x402 Micropayments.",
    version="1.0.0",
    contact={
        "name": "AgentRisk",
        "email": "m2m@agentrisk.dev",
    },
)

PAYMENT_WALLET = "0x42Baa7DEBbB71aFB90f14d0352F0390aE0C35ABB"
PRICE_USDC = "0.15"
from x402.extensions.bazaar import declare_discovery_extension, OutputConfig, bazaar_resource_server_extension
from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.server import x402ResourceServer

from x402.http import HTTPFacilitatorClient
from cdp.x402 import create_facilitator_config

x402_facilitator = HTTPFacilitatorClient(
    create_facilitator_config(
        api_key_id=os.environ.get("CDP_API_KEY_ID"),
        api_key_secret=os.environ.get("CDP_API_KEY_SECRET"),
    )
)
x402_server = x402ResourceServer(x402_facilitator)
x402_server.register("eip155:8453", ExactEvmServerScheme())
x402_server.register_extension(bazaar_resource_server_extension)

x402_routes: dict[str, RouteConfig] = {
    "GET /scan": RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                pay_to=PAYMENT_WALLET,
                price=f"${PRICE_USDC}",
                network="eip155:8453",
            ),
        ],
        mime_type="application/json",
        description="Detect honeypot, rug pull, scam, and fake tokens on Base before buying or swapping. Pre-trade contract safety check: mint function, blacklist function, transfer pausable, buy/sell tax, ownership renounced, LP locked or burned, holder concentration, deployer wallet history and reputation, brand impersonation. Returns risk score, confidence level, and clear buy/don't-buy verdict for autonomous trading agents on Base.",
        resource="https://agentrisk.dev/scan",
        extensions=declare_discovery_extension(
            input={"token": "0x4200000000000000000000000000000000000006"},
            input_schema={
                "properties": {"token": {"type": "string", "description": "Base token contract address (0x...)"}},
                "required": ["token"],
            },
            output=OutputConfig(
                example={"riskScore": 20, "riskLevel": "CAUTION", "shouldExecute": True},
            ),
        ),
    ),
    "POST /mcp/tools/check_token_risk": RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                pay_to=PAYMENT_WALLET,
                price=f"${PRICE_USDC}",
                network="eip155:8453",
            ),
        ],
        mime_type="application/json",
        description="Detect honeypot, rug pull, scam, and fake tokens on Base before buying or swapping (MCP tool). Pre-trade contract safety check: mint function, blacklist function, transfer pausable, buy/sell tax, ownership renounced, LP locked or burned, holder concentration, deployer wallet history and reputation, brand impersonation. Returns risk score, confidence level, and clear buy/don't-buy verdict for autonomous trading agents on Base.",
        resource="https://agentrisk.dev/mcp/tools/check_token_risk",
    ),
}

app.add_middleware(PaymentMiddlewareASGI, routes=x402_routes, server=x402_server)


from fastapi.staticfiles import StaticFiles
import os

from fastapi.responses import FileResponse

@app.get("/favicon.ico")
async def favicon():
    return FileResponse("favicon.ico")

os.makedirs(".well-known/mcp", exist_ok=True)
app.mount("/.well-known", StaticFiles(directory=".well-known"), name="well-known")
@app.get("/scan")
async def scan_token(token: str, request: Request, attest: bool = False):
    
    try:
        from rpc_manager import RPCManager
        rpc = RPCManager()
        analyzer = TokenAnalyzer(rpc_manager=rpc)
        report = await analyzer.analyze(token)
        await analyzer.aclose()
        has_critical_finding = any(f.severity == "critical" for f in report.findings)
        should_execute = report.risk_score <= 45 and not has_critical_finding
        tracker.log_scan(
            address=token,
            risk_score=report.risk_score,
            risk_level=report.risk_level.value,
            should_execute=should_execute,
            is_honeypot=bool(report.is_honeypot),
        )

        if report.creator_address:
            tracker.log_deployer(
                deployer_address=report.creator_address,
                token_address=token,
                risk_score=report.risk_score,
                is_honeypot=bool(report.is_honeypot),
            )
        report_dict = report.model_dump() if hasattr(report, "model_dump") else dict(report.__dict__)
        report_dict["should_execute"] = should_execute
        if attest:
            from attestation import sign_receipt
            receipt = sign_receipt(
                scan_id=report.scan_id,
                risk_score=report.risk_score,
                token_address=token,
                chain="base",
                timestamp=report.timestamp,
            )
            if receipt is not None:
                report_dict["attestation"] = receipt
        return report_dict
    except Exception as e:
        logger.error(f"Analysis error for {token}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan-trial")
async def scan_trial(token: str, wallet: str, request: Request):
    wallet = wallet.lower()
    if not wallet.startswith("0x") or len(wallet) != 42:
        raise HTTPException(status_code=400, detail="Invalid wallet address format.")

    used = tracker.count_free_trials(wallet)
    if used >= tracker.FREE_TRIAL_LIMIT:
        raise HTTPException(
            status_code=402,
            detail=f"Free trial limit ({tracker.FREE_TRIAL_LIMIT}) reached for this wallet. Use /scan with x402 payment (0.15 USDC) to continue."
        )

    try:
        from rpc_manager import RPCManager
        rpc = RPCManager()
        analyzer = TokenAnalyzer(rpc_manager=rpc)
        report = await analyzer.analyze(token)
        await analyzer.aclose()
        tracker.log_free_trial(wallet_address=wallet, token_address=token)
        return report
    except Exception as e:
        logger.error(f"Free trial analysis error for {token}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/test-x402.html", response_class=HTMLResponse)
async def test_x402_page():
    with open("static/test-x402.html") as f:
        return f.read()


@app.post("/verify")
async def verify_receipt(request: Request):
    body = await request.json()
    required_fields = ["scan_id", "risk_score", "input_digest", "rulepack_hash", "rulepack_version", "chain", "timestamp", "signer", "signature"]
    if not all(k in body for k in required_fields):
        return JSONResponse(content={"valid": False, "reason": "missing required fields"}, status_code=400)

    from eth_account import Account
    from eth_account.messages import encode_defunct
    from attestation import get_rulepack_hash

    receipt = {k: body[k] for k in required_fields if k != "signature"}
    signature = body["signature"]

    try:
        message_str = json.dumps(receipt, sort_keys=True)
        message = encode_defunct(text=message_str)
        recovered = Account.recover_message(message, signature=signature)
    except Exception as e:
        return JSONResponse(content={"valid": False, "reason": f"malformed signature: {e}"})

    expected_signer = os.environ.get("ATTESTATION_SIGNER_ADDRESS", "0x963E6bC84fAA5AF0a25CACA6a0B8257B5b78d840")
    signature_valid = recovered.lower() == expected_signer.lower() and recovered.lower() == body["signer"].lower()

    current_rulepack = get_rulepack_hash()
    rulepack_current = body["rulepack_hash"] == current_rulepack

    age_seconds = int(time.time()) - body["timestamp"]
    max_age_seconds = 24 * 60 * 60
    is_stale = age_seconds > max_age_seconds

    valid = signature_valid and not is_stale

    return JSONResponse(content={
        "valid": valid,
        "signature_valid": signature_valid,
        "signer": recovered if signature_valid else None,
        "rulepack_current": rulepack_current,
        "age_seconds": age_seconds,
        "stale": is_stale,
        "revoked": False,
    })


@app.get("/.well-known/agent.json")
async def get_agent_manifest():
    return JSONResponse(content={
        "name": "AgentRisk AI Threat Engine",
        "description": "Autonomous AI Risk & Threat Detection Engine for Web3 tokens and contracts.",
        "protocol": "x402",
        "endpoint": "https://agentrisk.dev/scan",
        "price_usdc": PRICE_USDC,
        "wallet": PAYMENT_WALLET
    })


@app.get("/v1/track-record")
async def track_record():
    """
    Returns public historical track record and aggregated accuracy stats
    for autonomous AI agents and developers.
    """
    return tracker.get_track_record_stats()


@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/index.html") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)


app.include_router(mcp_server.mcp_router)

from fastapi.responses import PlainTextResponse

@app.get("/llms.txt", response_class=PlainTextResponse)
async def get_llms_txt():

    llms_content = """# AgentRisk M2M

> Pre-Trade Decision API for Autonomous Agents operating on Base.

## Overview
AgentRisk M2M provides programmatic, machine-readable security decisions for autonomous AI agents before they execute on-chain token swaps or purchases.

## When to Use
Use this tool BEFORE executing any token purchase or swap on Base when the token contract is unknown or untrusted.

## Endpoint
- Base URL: https://agentrisk.dev
- Scan Endpoint: /scan?token=<CONTRACT_ADDRESS>
- Protocol: x402 Micropayment (0.15 USDC)

## Tool: check_token_refresh / check_token_risk
- Description: Checks whether a token on Base is safe enough for an autonomous agent to trade. Performs honeypot simulation, tax analysis, and deployer reputation checks.
- Returns: A deterministic execution recommendation (ALLOW, CAUTION, REJECT) with structured reasons, risk score, and confidence.
"""
    return llms_content



