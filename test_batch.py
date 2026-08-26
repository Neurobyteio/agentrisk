import asyncio
import json
import os

from dotenv import load_dotenv
from eth_account import Account
from x402 import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm import EthAccountSigner
from x402.mechanisms.evm.exact.register import register_exact_evm_client

load_dotenv()

PRIVATE_KEY = os.environ.get("TEST_PAYER_PRIVATE_KEY")
if not PRIVATE_KEY:
    raise RuntimeError("TEST_PAYER_PRIVATE_KEY not set in .env")

TOKENS = [
    "0xF36652cde978fF333b76cb4688ca88FB04eF5DdA",
    "0xB2000000000000000000003967bd404479E63656",
    "0xB20000000000000000000040d29e37E54435f101",
]


async def main():
    account = Account.from_key(PRIVATE_KEY)
    print(f"Плачу с кошелька: {account.address}\n")

    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(account))

    async with x402HttpxClient(client, timeout=60.0) as http:
        for token in TOKENS:
            url = f"https://agentrisk.dev/scan?token={token}"
            print(f"=== {token} ===")
            try:
                response = await http.get(url)
                if response.status_code == 200:
                    data = response.json()
                    print(f"  risk_score: {data.get('risk_score')}")
                    print(f"  risk_level: {data.get('risk_level')}")
                    print(f"  is_honeypot: {data.get('is_honeypot')}")
                    print(f"  is_contract: {data.get('is_contract')}")
                    print(f"  liquidity_usd: {data.get('liquidity_usd')}")
                    findings = data.get('findings', [])
                    for f in findings:
                        print(f"    - {f.get('message')}")
                else:
                    print(f"  Статус: {response.status_code}")
                    print(f"  {response.text[:300]}")
            except Exception as e:
                print(f"  Ошибка: {e}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
