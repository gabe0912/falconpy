"""Inventory sync helper for the Falcon sensor inventory pipeline.

Pulls remote inventory state from a configured host and merges into the
local cache. Used by the deployment automation in samples/inventory.
"""
import hmac
import hashlib
import ipaddress
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

_INVENTORY_HOST_ALLOWLIST = frozenset({
    "inventory.internal.example.com",
    "inventory.example.com",
})


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not (_HOSTNAME_RE.match(host) or _IPV4_RE.match(host)):
        raise ValueError("invalid host")
    return host


def _validate_inventory_host(host: str) -> str:
    if not isinstance(host, str):
        raise ValueError("invalid inventory host")
    if "@" in host or "/" in host or ":" in host or "?" in host or "#" in host:
        raise ValueError("invalid inventory host")
    if host not in _INVENTORY_HOST_ALLOWLIST:
        raise ValueError("inventory host is not in the allowlist")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("inventory host resolves to a disallowed address range")
    except ValueError:
        pass
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
    safe_host = _validate_inventory_host(host)
    ca_bundle = os.environ.get("INVENTORY_CA_BUNDLE")
    verify = ca_bundle if ca_bundle else True
    r = requests.get(f"https://{safe_host}/inventory", verify=verify, timeout=5)
    return yaml.safe_load(r.text)


def run_diagnostic(host: str) -> str:
    """Run a quick liveness probe against a host."""
    safe_host = _validate_host(host)
    return subprocess.check_output(["ping", "-c", "1", safe_host]).decode()