# AgentRisk M2M 🛡️

> **Pre-Trade Security Layer for Autonomous DeFi Agents on Base.** *Stop letting your autonomous trading bots get rekt by stealth honeypots, malicious taxes, and rugpulls.*

---

## ⚡ The Problem

Autonomous trading bots are fast, but they are completely blind.
Every minute, new unvetted tokens launch on Base. A significant share are deliberately engineered traps designed to block sells, drain executing wallets, or alter transfer taxes at the worst possible moment.
Static blocklists (like standard free APIs) are useless against freshly deployed, obfuscated contracts. By the time human-curated lists update, your bot's capital is already gone.

## 🎯 The Solution

**AgentRisk** is an isolated, machine-readable security API built specifically for AI agents and automated scripts.
Before your bot executes a `swap()` on Uniswap or Aerodrome, it pings AgentRisk. We run a deep runtime simulation combining direct on-chain checks, GoPlus Security, and DexScreener liquidity data, and return a strict verdict:

```json
{
  "riskScore": 20,
  "riskLevel": "CAUTION",
  "verdict": "PROCEED WITH CAUTION. Top 10 holders control 51.8% of supply.",
  "shouldExecute": true,
  "reasons": [
    "Top 10 holders control 51.8% of supply."
  ]
}
```

## What Makes This Different

- **Deployer wallet freshness** — flags newly-created wallets used for one-off token launches
- **Brand impersonation detection** — flags tokens named after known companies (Apple, Google, Meta, etc.)
- **Data source disagreement** — flags cases where third-party APIs and our own on-chain checks disagree
- **Human-readable verdict** — one plain-English sentence, not just raw scores
- **Sub-millisecond cached responses** — repeat scans within 30 seconds return instantly, with a `cached` field so you know whether a result is fresh or reused

## Quick Testing with MCP Inspector

Want to poke at the MCP server without writing any code? Run: npx @modelcontextprotocol/inspector

Then connect it to `https://agentrisk.dev/mcp/manifest` and call `check_token_risk` directly from the UI.

## Cache Freshness Warning

Every response includes `cached` (boolean) and `timestamp` (unix seconds) fields. Cached results are served for up to 30 seconds — long enough to speed up repeat lookups, short enough to catch a rug pull or a newly-enabled honeypot function in most cases. For the final safety check immediately before executing a trade, we recommend either calling with a fresh request or checking that `cached` is `false` / `timestamp` is very recent before trusting a `shouldExecute: true` result.

## ⚙️ How It Works (M2M Architecture)

1. Agent Discovers Token via mempool or DEX router event.
2. Agent Calls AgentRisk MCP Tool (`check_token_risk`) or the direct `/scan` endpoint.
3. Instant x402 Micropayment ($0.15 USDC instantly settled on Base — no API keys, subscriptions, or credit cards; pure machine-to-machine payment).
4. Binary Decision: The agent receives `shouldExecute: true/false` with a risk score and structured reasons.

## 📦 Python SDK

```bash
pip install agentriskm2m
```

```python
import asyncio
from agentrisk import AgentRisk

async def main():
    risk = AgentRisk(private_key="your_base_wallet_private_key")
    result = await risk.scan("0xTokenAddressHere")
    print(result["verdict"])

asyncio.run(main())
```

[PyPI page](https://pypi.org/project/agentriskm2m/)

## 🚀 Copy-Paste Integration (60 seconds)

Install the x402 SDK, then run this — it handles payment automatically:

```python
pip install x402 eth-account

import asyncio
from eth_account import Account
from x402 import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm import EthAccountSigner
from x402.mechanisms.evm.exact.register import register_exact_evm_client

PRIVATE_KEY = "your_base_wallet_private_key"
TOKEN_ADDRESS = "0x..."  # the token you want to check

async def check_token():
    account = Account.from_key(PRIVATE_KEY)
    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(account))
    async with x402HttpxClient(client) as http:
        response = await http.get(f"https://agentrisk.dev/scan?token={TOKEN_ADDRESS}")
        print(response.json())

asyncio.run(check_token())
```

That's it. It pays 0.15 USDC automatically and prints the risk report. Your wallet needs a small amount of USDC and ETH (for gas) on Base.

## Framework Integration Examples

### Option 1: MCP (Claude, Cursor, any MCP-compatible agent)

No code needed — just point your MCP client config at:

```json
{
  "mcpServers": {
    "agentrisk": {
      "url": "https://agentrisk.dev/mcp/manifest"
    }
  }
}
```

Your agent will automatically discover `check_token_risk` as an available tool.

### Option 2: LangChain

```python
from langchain.tools import tool
from eth_account import Account
from x402 import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm import EthAccountSigner
from x402.mechanisms.evm.exact.register import register_exact_evm_client

account = Account.from_key("your_base_wallet_private_key")
client = x402Client()
register_exact_evm_client(client, EthAccountSigner(account))

@tool
async def check_token_safety(token_address: str) -> dict:
    """Check if a Base token is a honeypot or scam before buying or swapping."""
    async with x402HttpxClient(client) as http:
        response = await http.get(f"https://agentrisk.dev/scan?token={token_address}")
        return response.json()

# Add check_token_safety to your agent's tools list
```

### Option 3: Coinbase AgentKit

```python
from coinbase_agentkit import action

@action(
    name="check_token_safety",
    description="Check if a Base token is safe to trade before executing a swap"
)
async def check_token_safety(token_address: str) -> dict:
    async with x402HttpxClient(client) as http:
        response = await http.get(f"https://agentrisk.dev/scan?token={token_address}")
        return response.json()
```

### Option 4: Plain Python (any custom bot, no framework)

```python
def buy_token(token_address, amount):
    risk = check_token_safety(token_address)  # your call to AgentRisk
    if not risk["shouldExecute"]:
        print(f"Blocked: {risk['verdict']}")
        return
    execute_swap(token_address, amount)
```

### Option 5: Automatic discovery via x402 Bazaar

If your agent searches the [x402 Bazaar](https://x402bazaar.xyz) for tools, AgentRisk is discoverable automatically — no manual integration needed.

## 🚀 Other Integration Options

### Option 1: MCP Server (For Claude, Cursor & Custom Agents)

MCP manifest is live at:
https://agentrisk.dev/mcp/manifest

Tool endpoint: `POST https://agentrisk.dev/mcp/tools/check_token_risk` (x402-gated, 0.15 USDC per call). ### Option 2: Direct HTTP Call

GET https://agentrisk.dev/scan?token=<CONTRACT_ADDRESS>

Returns HTTP 402 with payment instructions until a valid x402 payment (0.15 USDC on Base) is attached.

## 💰 Economy

- **Model:** Pay-per-scan via the x402 protocol on Base Mainnet.
- **Cost:** 0.15 USDC per comprehensive scan.
- **Facilitator:** Coinbase's official CDP facilitator — verifies and settles payments directly on Base.

## 🔎 Live Status

- Agent manifest: [`/​.well-known/agent.json`](https://agentrisk.dev/.well-known/agent.json)
- MCP manifest: [`/mcp/manifest`](https://agentrisk.dev/mcp/manifest)
- Public track record: [`/v1/track-record`](https://agentrisk.dev/v1/track-record)
- Listed on the [x402 Bazaar](https://x402bazaar.xyz) — discoverable by any agent searching for token safety tools

Built for autonomous systems that trust math, not hype.
