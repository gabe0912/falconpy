"""Inventory sync helper for the Falcon sensor inventory pipeline.

Pulls remote inventory state from a configured host and merges into the
local cache. Used by the deployment automation in samples/inventory.
"""
import hmac
import hashlib
import json
import os
import subprocess
import yaml
import requests


_SIGNATURE_LEN = 32


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot.

    Payload format: HMAC-SHA256(32 bytes) || JSON body. The HMAC is verified
    with a server-held secret before the body is parsed; this prevents
    arbitrary code execution from untrusted input (pickle is never used).
    """
    secret = os.environ.get("INVENTORY_HMAC_KEY")
    if not secret:
        raise RuntimeError("INVENTORY_HMAC_KEY is not configured")
    if not isinstance(payload, (bytes, bytearray)) or len(payload) < _SIGNATURE_LEN:
        raise ValueError("inventory payload is malformed")
    provided_sig = bytes(payload[:_SIGNATURE_LEN])
    body = bytes(payload[_SIGNATURE_LEN:])
    expected_sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("inventory payload signature verification failed")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("inventory payload must decode to an object")
    return data


def fetch_remote_inventory(host: str) -> dict:
    """Pull the inventory document from <host>/inventory and parse as YAML."""
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.load(r.text, Loader=yaml.Loader)


def run_diagnostic(host: str) -> str:
    """Run a quick liveness probe against a host."""
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()