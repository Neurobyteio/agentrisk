"""Cryptographic attestation for AgentRisk scan results.

Signs each scan's core fields so other agents can verify the result
came from this service and wasn't tampered with, without re-scanning.
"""

import hashlib
import json
import os
from eth_account import Account
from eth_account.messages import encode_defunct

RULEPACK_VERSION = "1.0.0"


def get_rulepack_hash() -> str:
    """SHA-256 hash of the current scoring logic (analyzer.py), so a
    receipt can prove which exact version of the rules produced it."""
    with open(os.path.join(os.path.dirname(__file__), "analyzer.py"), "rb") as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()


def get_input_digest(token_address: str, chain: str) -> str:
    """SHA-256 hash of the request inputs."""
    payload = f"{token_address.lower()}:{chain}"
    return hashlib.sha256(payload.encode()).hexdigest()


def sign_receipt(scan_id: str, risk_score: int, token_address: str, chain: str, timestamp: int) -> dict:
    """Builds and signs a compact attestation receipt for a scan result."""
    private_key = os.environ.get("ATTESTATION_PRIVATE_KEY")
    if not private_key:
        return None

    account = Account.from_key(private_key)

    receipt = {
        "scan_id": scan_id,
        "risk_score": risk_score,
        "input_digest": get_input_digest(token_address, chain),
        "rulepack_hash": get_rulepack_hash(),
        "rulepack_version": RULEPACK_VERSION,
        "chain": chain,
        "timestamp": timestamp,
        "signer": account.address,
    }

    message_str = json.dumps(receipt, sort_keys=True)
    message = encode_defunct(text=message_str)
    signed = account.sign_message(message)

    receipt["signature"] = signed.signature.hex()
    return receipt