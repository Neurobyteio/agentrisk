"""
test_x402_client.py

Честная сквозная проверка: реально платит 0.15 USDC в сети Base
на agentrisk.dev/scan и печатает, что сервис ответил.
"""

import asyncio
import base64
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

TARGET_URL = "https://agentrisk.dev/scan?token=0xAd46308a6f6999BaCc099F3029B77c352E772ba3&attest=true&attest=true"


async def main():
    account = Account.from_key(PRIVATE_KEY)
    print(f"Плачу с кошелька: {account.address}")

    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(account))

    async with x402HttpxClient(client, timeout=60.0) as http:
        print("Отправляю запрос и оплачиваю по-настоящему...")
        response = await http.get(TARGET_URL)
        print(f"Статус ответа: {response.status_code}")

        if response.status_code == 402:
            header = response.headers.get("payment-required")
            if header:
                padded = header + "=" * (-len(header) % 4)
                decoded = base64.b64decode(padded)
                print("Причина отказа (расшифровано):")
                print(json.dumps(json.loads(decoded), indent=2, ensure_ascii=False))
            else:
                print("Заголовок payment-required отсутствует.")
        else:
            print("Ответ сервера:")
            print(response.text)


if __name__ == "__main__":
    asyncio.run(main())
