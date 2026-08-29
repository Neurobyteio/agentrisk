"""AgentRisk Python SDK — pre-trade risk scoring for Base tokens via x402."""

from eth_account import Account
from x402 import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm import EthAccountSigner
from x402.mechanisms.evm.exact.register import register_exact_evm_client


class AgentRisk:
    """
    Client for the AgentRisk pre-trade token safety API on Base.

    Usage:
        risk = AgentRisk(private_key="0x...")
        result = await risk.scan("0xTokenAddress...")
    """

    def __init__(self, private_key: str, base_url: str = "https://agentrisk.dev"):
        self.base_url = base_url.rstrip("/")
        account = Account.from_key(private_key)
        self._client = x402Client()
        register_exact_evm_client(self._client, EthAccountSigner(account))

    async def scan(self, token_address: str) -> dict:
        """
        Check a Base token for honeypot status, deployer freshness, brand
        impersonation, and LP lock status. Pays 0.15 USDC on Base via x402.

        Returns a dict with riskScore, riskLevel, verdict, shouldExecute,
        confidence, and structured findings.
        """
        async with x402HttpxClient(self._client, timeout=60.0) as http:
            response = await http.get(f"{self.base_url}/scan?token={token_address}")
            response.raise_for_status()
            return response.json()
