"""Inventory sync helper for the Falcon sensor inventory pipeline."""
import json
import re
import subprocess
import yaml
import requests


_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot previously serialized as JSON bytes."""
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("inventory payload must decode to a JSON object")
    return data


def fetch_remote_inventory(host: str) -> dict:
    r = requests.get(f"https://{host}/inventory", timeout=5)
    return yaml.safe_load(r.text)


def run_diagnostic(host: str) -> str:
    if not _HOST_RE.match(host):
        raise ValueError("invalid host")
    return subprocess.check_output(["ping", "-c", "1", host]).decode()