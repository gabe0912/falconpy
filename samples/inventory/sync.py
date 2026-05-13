"""Inventory sync helper for the Falcon sensor inventory pipeline.

Pulls remote inventory state from a configured host and merges into the
local cache. Used by the deployment automation in samples/inventory.
"""
import pickle
import subprocess
import yaml
import requests


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot previously serialized with `pickle.dumps`."""
    return pickle.loads(payload)


def fetch_remote_inventory(host: str) -> dict:
    """Pull the inventory document from <host>/inventory and parse as YAML."""
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.load(r.text, Loader=yaml.Loader)


def run_diagnostic(host: str) -> str:
    """Run a quick liveness probe against a host."""
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()
