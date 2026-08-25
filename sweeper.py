import os
from web3 import Web3

# Подключение к сети Base
w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))

# Адрес накопителя (куда платят клиенты)
TREASURY_ADDRESS = "0x72C296742Ef55b8cCF50a11b3ac5cB25834A6FE5"

# Твой приватный ключ
import os
from dotenv import load_dotenv
load_dotenv()
PRIVATE_KEY = os.environ.get("SWEEPER_PRIVATE_KEY")

# Адрес Bybit (куда улетит сумма при достижении порога)
BYBIT_ADDRESS = "0xd33e763e6974db2cd0ca0d91349dc8a646c9d43b"

# Адрес смарт-контракта USDC в сети Base
USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# Порог для автовывода (50 USDC)
THRESHOLD_USDC = 50.0  
THRESHOLD_WEI = int(THRESHOLD_USDC * 10**6)

USDC_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function"
    }
]

def sweep_funds():
    if not w3.is_connected():
        print("Ошибка: Нет связи с RPC сети Base")
        return

    usdc_contract = w3.eth.contract(address=Web3.to_checksum_address(USDC_ADDRESS), abi=USDC_ABI)
    
    # Проверяем баланс на накопителе
    balance = usdc_contract.functions.balanceOf(Web3.to_checksum_address(TREASURY_ADDRESS)).call()
    print(f"Текущий баланс накопителя: {balance / 10**6} USDC")

    if balance < THRESHOLD_WEI:
        print(f"Баланс меньше {THRESHOLD_USDC} USDC. Ждем накопления...")
        return

    print(f"Порог в {THRESHOLD_USDC} USDC достигнут! Отправляем на Bybit...")

    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(TREASURY_ADDRESS))
    
    txn = usdc_contract.functions.transfer(
        Web3.to_checksum_address(BYBIT_ADDRESS),
        balance
    ).build_transaction({
        'chainId': 8453,
        'gas': 100000,
        'gasPrice': w3.eth.gas_price,
        'nonce': nonce,
    })

    signed_txn = w3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"Транзакция отправлена на Bybit! Хэш: {w3.to_hex(tx_hash)}")

if __name__ == "__main__":
    sweep_funds()

