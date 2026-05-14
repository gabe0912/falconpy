"""Inventory sync helper for the Falcon sensor inventory pipeline."""
import json
import subprocess
import yaml
import requests


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot previously serialized as JSON."""
    return json.loads(payload)


def fetch_remote_inventory(host: str) -> dict:
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.load(r.text, Loader=yaml.Loader)


def run_diagnostic(host: str) -> str:
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()