import asyncio
from cdp import CdpClient, parse_units
from dotenv import load_dotenv
import os
import sys

load_dotenv('/var/www/agentrisk/.env')

BYBIT_ADDRESS = "0xd33e763e6974db2cd0ca0d91349dc8a646c9d43b"
WALLET_NAME = "agentrisk-payment-wallet"

async def main():
    destination = sys.argv[1] if len(sys.argv) > 1 else BYBIT_ADDRESS
    amount_usdc = sys.argv[2] if len(sys.argv) > 2 else "0.1"

    async with CdpClient(
        api_key_id=os.environ["CDP_API_KEY_ID"],
        api_key_secret=os.environ["CDP_API_KEY_SECRET"],
        wallet_secret=os.environ["CDP_WALLET_SECRET"],
    ) as cdp:
        accounts = await cdp.evm.list_accounts()
        account = next(a for a in accounts.accounts if a.name == WALLET_NAME)

        print(f"Кошелёк: {account.address}")
        print(f"Отправляю {amount_usdc} USDC на: {destination}")

        confirm = input("Подтвердите перевод (да/нет): ")
        if confirm.lower() not in ("да", "yes", "y"):
            print("Отменено.")
            return

        tx_hash = await account.transfer(
            to=destination,
            amount=parse_units(amount_usdc, 6),
            token="usdc",
            network="base",
        )
        print(f"Готово. Хэш транзакции: {tx_hash}")

asyncio.run(main())