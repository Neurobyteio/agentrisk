import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from analyzer import TokenAnalyzer
from rpc_manager import RPCManager

mcp_router = APIRouter()


class TokenCheckRequest(BaseModel):
    token_address: str


@mcp_router.post("/mcp/tools/check_token_risk")
async def mcp_check_token_risk(payload: TokenCheckRequest):
    """
    MCP Tool: Inspects a Web3 token on Base network for honeypot and rugpull risks.
    Returns an autonomous decision object for AI agents.
    """
    token = payload.token_address
    if not token or not token.startswith("0x"):
        raise HTTPException(status_code=400, detail="Invalid token address format")

    try:
        rpc = RPCManager()
        analyzer = TokenAnalyzer(rpc_manager=rpc)
        report = await analyzer.analyze(token)
        await analyzer.aclose()

        should_execute = report.risk_score <= 45
        decision = {
            "shouldExecute": should_execute,
            "riskScore": report.risk_score,
            "riskLevel": report.risk_level.value,
            "reasons": [f.message for f in report.findings],
        }
        return {
            "tool": "check_token_risk",
            "status": "success",
            "decision": decision
        }
    except Exception as e:
        return {
            "tool": "check_token_risk",
            "status": "error",
            "message": str(e)
        }


@mcp_router.get("/mcp/manifest")
async def mcp_manifest():
    """
    MCP Server Manifest for AI Agent discovery.
    """
    return {
        "name": "AgentRisk M2M",
        "version": "1.0.0",
        "protocol": "mcp",
        "description": "Pre-Trade Decision API for Autonomous Agents on Base. Deterministic honeypot risk analysis.",
        "endpoints": {
            "check_token_risk": "https://agentrisk.dev/mcp/tools/check_token_risk"
        },
        "tools": [
            {
                "name": "check_token_risk",
                "description": "Use this tool BEFORE executing a token swap on Base. Returns a risk score and shouldExecute decision with structured reasons. Requires x402 payment.",
                "parameters": {
                    "token_address": "string (Base contract address)"
                }
            }
        ]
    }
