import os, subprocess, shutil

sdk_dir = "/var/www/agentrisk/agentrisk_sdk"
if os.path.exists(sdk_dir):
    shutil.rmtree(sdk_dir)

os.makedirs(f"{sdk_dir}/agentrisk", exist_ok=True)

with open(f"{sdk_dir}/agentrisk/__init__.py", "w") as f:
    f.write('import httpx\n\nclass AgentRisk:\n    def __init__(self, base_url: str = "https://api.agentrisk.dev"):\n        self.base_url = base_url.rstrip("/")\n\n    def quick_scan(self, token_address: str) -> dict:\n        response = httpx.get(f"{self.base_url}/v1/token/quick", params={"address": token_address})\n        response.raise_for_status()\n        return response.json()\n\n    def deep_scan(self, token_address: str, tx_hash: str = None) -> dict:\n        params = {"address": token_address}\n        if tx_hash:\n            params["tx_hash"] = tx_hash\n        response = httpx.get(f"{self.base_url}/v1/token/deep", params=params)\n        return {"status_code": response.status_code, "data": response.json()}\n')

with open(f"{sdk_dir}/README.md", "w") as f:
    f.write("# AgentRisk Python SDK\n\nOfficial Python client for AgentRisk API on Base Network.\n\n## Installation\n```bash\npip install agentrisk\n```\n")

with open(f"{sdk_dir}/pyproject.toml", "w") as f:
    f.write('[build-system]\nrequires = ["setuptools>=61.0"]\nbuild-backend = "setuptools.build_meta"\n\n[project]\nname = "agentrisk-base-v1"\nversion = "1.0.0"\ndescription = "Token risk scoring and honeypot detection API for Base Network"\nreadme = "README.md"\nrequires-python = ">=3.8"\ndependencies = ["httpx>=0.24.0"]\nkeywords = ["base", "crypto", "honeypot", "security", "ai-agent", "x402"]\n')

import os
token = os.environ.get("PYPI_TOKEN")
if not token:
    raise RuntimeError("PYPI_TOKEN not set in environment (.env)")
subprocess.run(["/var/www/agentrisk/venv/bin/python3", "-m", "build"], cwd=sdk_dir, check=True)
subprocess.run(["/var/www/agentrisk/venv/bin/python3", "-m", "twine", "upload", "dist/*", "-u", "__token__", "-p", token], cwd=sdk_dir, check=True)

print("\nSUCCESS: Package successfully published to PyPI!")
