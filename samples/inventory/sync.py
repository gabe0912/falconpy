"""Inventory sync helper for the Falcon sensor inventory pipeline."""
import pickle
import re
import subprocess
import yaml
import requests


_HOST_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot previously serialized with pickle.dumps."""
    return pickle.loads(payload)


def fetch_remote_inventory(host: str) -> dict:
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.safe_load(r.text)


def run_diagnostic(host: str) -> str:
    if not _HOST_RE.match(host):
        raise ValueError("invalid host")
    return subprocess.check_output(["ping", "-c", "1", host]).decode()