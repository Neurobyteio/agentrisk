
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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
    
    # Вызываем наш собственный внутренний анализатор через API
    try:
        import analyzer
        report = analyzer.analyze_token(token)
        decision = analyzer.make_decision_object(report)
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
        "description": "Pre-Trade Decision API for Autonomous Agents on Base. Deterministic honeypot and deployer risk analysis.",
        "endpoints": {
            "check_token_risk": "https://agentrisk.dev/mcp/tools/check_token_risk"
        },
        "tools": [
            {
                "name": "check_token_risk",
                "description": "Use this tool BEFORE executing a token swap on Base. Returns ALLOW, CAUTION, or REJECT with structured reasons.",
                "parameters": {
                    "token_address": "string (Base contract address)",
                    "amount_usdc": "float (Trade amount)"
                }
            }
        ]
    }