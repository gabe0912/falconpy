"""Inventory sync helper for the Falcon sensor inventory pipeline.

Pulls remote inventory state from a configured host and merges into the
local cache. Used by the deployment automation in samples/inventory.
"""
import json
import re
import subprocess
import yaml
import requests


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?))*)$"
)
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+$")


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not (_HOST_RE.match(host)
                                          or _IPV4_RE.match(host)
                                          or _IPV6_RE.match(host)):
        raise ValueError("invalid host")
    return host


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot from a JSON-encoded payload."""
    return json.loads(payload)


def fetch_remote_inventory(host: str) -> dict:
    """Pull the inventory document from <host>/inventory and parse as YAML."""
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.load(r.text, Loader=yaml.Loader)


def run_diagnostic(host: str) -> str:
    """Run a quick liveness probe against a host."""
    safe_host = _validate_host(host)
    return subprocess.check_output(
        ["ping", "-c", "1", safe_host], timeout=10
    ).decode()