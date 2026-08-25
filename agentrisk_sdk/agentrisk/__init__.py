import httpx

class AgentRisk:
    def __init__(self, base_url: str = "https://api.agentrisk.dev"):
        self.base_url = base_url.rstrip("/")

    def quick_scan(self, token_address: str) -> dict:
        response = httpx.get(f"{self.base_url}/v1/token/quick", params={"address": token_address})
        response.raise_for_status()
        return response.json()

    def deep_scan(self, token_address: str, tx_hash: str = None) -> dict:
        params = {"address": token_address}
        if tx_hash:
            params["tx_hash"] = tx_hash
        response = httpx.get(f"{self.base_url}/v1/token/deep", params=params)
        return {"status_code": response.status_code, "data": response.json()}
