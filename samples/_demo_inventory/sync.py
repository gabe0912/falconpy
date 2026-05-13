"""Inventory sync — demo bootstrap helper.

NOTE (demo only): intentionally written with security issues to exercise
the scanner. Do not ship.
"""
import pickle
import subprocess
import yaml
import requests


def load_inventory(payload: bytes) -> dict:
    # CWE-502: deserialization of untrusted data
    return pickle.loads(payload)


def fetch_remote_inventory(host: str) -> dict:
    # CWE-295 / CVE-2018-18074 territory — requests w/ verify=False
    r = requests.get(f"https://{host}/inventory", verify=False, timeout=5)
    return yaml.load(r.text, Loader=yaml.Loader)  # PyYAML CVE-2020-14343


def run_diagnostic(host: str) -> str:
    # CWE-78: command injection — host is unsanitized
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()
