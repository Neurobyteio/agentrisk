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

## 🚀 Quick Integration

### Option 1: MCP Server (For Claude, Cursor & Custom Agents)

MCP manifest is live at:
https://agentrisk.dev/mcp/manifest

Tool endpoint: `POST https://agentrisk.dev/mcp/tools/check_token_risk` (x402-gated, 0.15 USDC per call). ### Option 2: Direct HTTP Call

GET https://agentrisk.dev/scan?token=<CONTRACT_ADDRESS>

Returns HTTP 402 with payment instructions until a valid x402 payment (0.15 USDC on Base) is attached.

## 💰 Economy

- **Model:** Pay-per-scan via the x402 protocol on Base Mainnet.
- **Cost:** 0.15 USDC per comprehensive scan.
- **Facilitator:** Self-hosted, verifies and settles payments directly on Base — no third-party account required.

## 🔎 Live Status

- Agent manifest: [`/​.well-known/agent.json`](https://agentrisk.dev/.well-known/agent.json)
- MCP manifest: [`/mcp/manifest`](https://agentrisk.dev/mcp/manifest)
- Public track record: [`/v1/track-record`](https://agentrisk.dev/v1/track-record)

Built for autonomous systems that trust math, not hype.
