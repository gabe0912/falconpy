"""Inventory sync helper for the Falcon sensor inventory pipeline.

Pulls remote inventory state from a configured host and merges into the
local cache. Used by the deployment automation in samples/inventory.
"""
import hmac
import hashlib
import json
import os
import re
import subprocess
import yaml
import requests


_SIGNATURE_LEN = 32

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)\.)*"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)$"
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not (_HOSTNAME_RE.match(host) or _IPV4_RE.match(host)):
        raise ValueError("invalid host")
    return host


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
    safe_host = _validate_host(host)
    return subprocess.check_output(["ping", "-c", "1", safe_host]).decode()