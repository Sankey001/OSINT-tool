"""Shared HTTP helpers: one session, sane timeouts, and a guard against
pointing the tool at private/internal addresses."""

import ipaddress
import socket

import requests

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 12

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"})


def session():
    return _session


def get(url, **kwargs):
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    return _session.get(url, **kwargs)


def get_json(url, **kwargs):
    resp = get(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


def host_is_public(host):
    """True when every address the host resolves to is publicly routable.
    Used before the tool makes direct connections (web/TLS probes)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable locally; let the request fail naturally.
        return True
    return all(is_public_ip(info[4][0]) for info in infos)
