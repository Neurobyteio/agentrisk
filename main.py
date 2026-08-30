from __future__ import annotations
import tracker
import os
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
async def scan_token(token: str, request: Request):
    
    try:
        from rpc_manager import RPCManager
        rpc = RPCManager()
        analyzer = TokenAnalyzer(rpc_manager=rpc)
        report = await analyzer.analyze(token)
        await analyzer.aclose()
        should_execute = report.risk_score <= 45
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
        return report
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
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="base:app_id" content="6a92aa67affbbc90e48885f2" />
        <title>AgentRisk AI Threat Engine</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: #1e293b; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); width: 100%; max-width: 520px; box-sizing: border-box; }
            h1 { font-size: 24px; margin-bottom: 8px; color: #38bdf8; }
            p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; line-height: 1.5; }
            .badge { background: #0369a1; color: #e0f2fe; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; display: inline-block; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; font-size: 14px; margin-bottom: 15px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; border-radius: 6px; border: none; background: #0284c7; color: #fff; font-weight: bold; font-size: 14px; cursor: pointer; transition: background 0.2s; }
            button:hover { background: #0369a1; }
            #result { margin-top: 20px; background: #0f172a; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; white-space: pre-wrap; display: none; max-height: 250px; overflow-y: auto; color: #38bdf8; border: 1px solid #334155; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>AgentRisk AI Threat Engine</h1>
            <p>M2M Security API protecting autonomous trading AI agents from honeypots on Base network.</p>
            
            <div class="badge">⚙️ x402 Protocol Gateway • 0.15 USDC per request</div>

            <input type="text" id="tokenAddress" placeholder="Enter contract address (0x...)">
            <button onclick="checkToken()">Test API Request</button>
            <p style="font-size:12px;color:#64748b;margin-top:10px;margin-bottom:0;">
                Note: this button demonstrates a real API call, but the browser can't pay automatically.
                Clicking it will show a genuine 402 Payment Required response — this is how the API is
                supposed to behave for a request with no payment attached. See
                <a href="https://github.com/Neurobyteio/agentrisk" style="color:#38bdf8;">the GitHub repo</a>
                for code that actually pays and gets a result.
            </p>
            <div id="result"></div>
        </div>

        <script>
            async function checkToken() {
                const address = document.getElementById('tokenAddress').value;
                const resultDiv = document.getElementById('result');
                if (!address) { alert('Please enter a contract address'); return; }
                
                resultDiv.style.display = 'block';
                resultDiv.innerText = 'Sending API request...';
                
                try {
                    const response = await fetch(`/scan?token=${address}`);
                    if (response.status === 402) {
                        resultDiv.innerText = "This endpoint is paid via the x402 protocol (0.15 USDC on Base). A regular browser click can't complete the payment automatically \u2014 you're seeing a real 402 Payment Required response, not an error or a broken API. To actually get a result, you need an x402-aware client that can sign and send a USDC payment: a script using a library like x402-fetch (JS) or the x402 Python SDK, or an AI agent/MCP client configured with a Base wallet. See the README on GitHub for working code examples: https://github.com/Neurobyteio/agentrisk";
                        return;
                    }
                    const data = await response.json();
                    resultDiv.innerText = JSON.stringify(data, null, 2);
                } catch (err) {
                    resultDiv.innerText = 'Request error: ' + err;
                }
            }
        </script>
    </body>
    </html>
    """

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



