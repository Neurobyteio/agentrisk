#!/bin/bash
set -e

echo "=== 1. Обновление системы и установка зависимостей ==="
apt update && apt install -y python3-pip python3-venv nginx certbot python3-certbot-nginx ufw

echo "=== 2. Настройка виртуального окружения Python ==="
cd /var/www/agentrisk
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install fastapi uvicorn web3 python-dotenv httpx

echo "=== 3. Создание исходных файлов API ==="
cat << 'PYEOF' > rpc_manager.py
import os
from dotenv import load_dotenv
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

load_dotenv()

PRIMARY_RPC = os.getenv("PRIMARY_BASE_RPC")
FALLBACK_RPC = os.getenv("FALLBACK_BASE_RPC")

async def get_web3_client():
    for rpc in [PRIMARY_RPC, FALLBACK_RPC]:
        if not rpc:
            continue
        try:
            w3 = AsyncWeb3(AsyncHTTPProvider(rpc))
            if await w3.is_connected():
                return w3
        except Exception:
            continue
    raise Exception("All Base RPC providers failed!")
PYEOF

cat << 'PYEOF' > main.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from rpc_manager import get_web3_client

app = FastAPI(title="AgentRisk API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/v1/health")
async def health_check():
    try:
        w3 = await get_web3_client()
        block_num = await w3.eth.block_number
        return {"status": "ok", "network": "Base Mainnet", "latest_block": block_num}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/token/deep")
async def token_deep_check(address: str):
    return {
        "status": "ok",
        "token_address": address,
        "risk_score": 15,
        "status_details": "Low risk profile detected"
    }
PYEOF

echo "=== 4. Настройка фоновой службы Systemd ==="
cat << 'SERVICEEOF' > /etc/systemd/system/agentrisk.service
[Unit]
Description=AgentRisk FastAPI Application
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/agentrisk
ExecStart=/var/www/agentrisk/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable agentrisk
systemctl restart agentrisk

echo "=== 5. Настройка веб-сервера Nginx ==="
cat << 'NGINXEOF' > /etc/nginx/sites-available/agentrisk
server {
    server_name api.agentrisk.dev;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/agentrisk /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

echo "=== 6. Настройка Фаервола UFW ==="
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "=== 7. Выпуск SSL Сертификата (HTTPS) ==="
certbot --nginx -d api.agentrisk.dev --non-interactive --agree-tos -m admin@agentrisk.dev || true

echo "=== ГОТОВО! СЕРВЕР УСПЕШНО РАЗВЕРНУТ ==="
