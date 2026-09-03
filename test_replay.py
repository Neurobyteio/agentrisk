import asyncio
import httpx
import json

receipt = {
    "scan_id": "acf343c4-2173-4d28-8900-d703c5db4690",
    "risk_score": 20,
    "input_digest": "cfc991d861bb66ae3b051ef96c957499bd2b7aa4b3d113c1f16319db54e40d19",
    "rulepack_hash": "113815e1989537d3aa115d2cd73b186d9c03e88d8385b6d2a44a4cb51679d314",
    "rulepack_version": "1.0.0",
    "chain": "base",
    "timestamp": 1788461356,
    "signer": "0x963E6bC84fAA5AF0a25CACA6a0B8257B5b78d840",
    "signature": "cc17bfd4ddb05d8f34932e71e349bdac9695a2c8e995886c7804fb05080e11bf582f50fc36e731da29f903ae13e6cbc14570363ccfc28f54b7d38d3c4066abe11b"
}

async def main():
    async with httpx.AsyncClient() as client:
        resp1 = await client.post("https://agentrisk.dev/verify", json=receipt)
        d1 = resp1.json()
        print("Первый вызов - valid:", d1.get("valid"), "failure_reason:", d1.get("failure_reason"))

        resp2 = await client.post("https://agentrisk.dev/verify", json=receipt)
        d2 = resp2.json()
        print("Второй вызов - valid:", d2.get("valid"), "failure_reason:", d2.get("failure_reason"))

asyncio.run(main())