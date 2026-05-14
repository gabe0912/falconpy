"""Inventory sync helper for the Falcon sensor inventory pipeline."""
import ipaddress
import json
import re
import socket
import subprocess
import yaml
import requests


_HOST_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")

_ALLOWED_INVENTORY_HOSTS = frozenset({
    "inventory.falcon.internal.example.com",
    "inventory-primary.falcon.example.com",
    "inventory-secondary.falcon.example.com",
})


def load_inventory(payload: bytes) -> dict:
    """Restore an inventory snapshot from a JSON-encoded payload."""
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("inventory payload must decode to an object")
    return data


def _is_disallowed_address(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def fetch_remote_inventory(host: str) -> dict:
    if host not in _ALLOWED_INVENTORY_HOSTS:
        raise ValueError("host is not in the inventory service allowlist")
    try:
        addrinfos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("unable to resolve inventory host") from exc
    for info in addrinfos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            raise ValueError("resolved address is not a valid IP")
        if _is_disallowed_address(ip):
            raise ValueError("resolved address is in a disallowed range")
    r = requests.get(f"https://{host}/inventory", timeout=5)
    return yaml.safe_load(r.text)


def run_diagnostic(host: str) -> str:
    if not _HOST_RE.match(host):
        raise ValueError("invalid host")
    return subprocess.check_output(["ping", "-c", "1", host]).decode()