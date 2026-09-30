"""Work out what kind of target the user typed."""

import ipaddress
import re
from urllib.parse import urlparse

TYPES = ("domain", "ip", "email", "username", "phone", "hash", "name")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9\-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)
PHONE_RE = re.compile(r"^\+?[\d\s().\-]{7,20}$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")
HASH_LENGTHS = {32, 40, 56, 64, 96, 128}
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_.\-]{2,40}$")


def normalize(raw, forced_type=None):
    """Return (type, value) for a raw query string."""
    value = (raw or "").strip()
    if not value:
        raise ValueError("Empty target")

    if forced_type:
        if forced_type not in TYPES:
            raise ValueError(f"Unknown target type: {forced_type}")
        return forced_type, _clean(forced_type, value)

    # URLs collapse to their host.
    if re.match(r"^[a-z][a-z0-9+.\-]*://", value, re.I):
        host = urlparse(value).hostname or ""
        if host:
            value = host

    if EMAIL_RE.match(value):
        return "email", value.lower()

    candidate = value.strip("[]")
    try:
        return "ip", str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    if HASH_RE.match(value) and len(value) in HASH_LENGTHS:
        return "hash", value.lower()

    if DOMAIN_RE.match(value.rstrip(".")):
        return "domain", value.rstrip(".").lower()

    digits = re.sub(r"\D", "", value)
    if PHONE_RE.match(value) and 7 <= len(digits) <= 15:
        return "phone", _clean("phone", value)

    if USERNAME_RE.match(value):
        return "username", value.lstrip("@")

    return "name", " ".join(value.split())


def _clean(kind, value):
    if kind == "domain":
        if "://" in value:
            value = urlparse(value).hostname or value
        return value.rstrip(".").lower()
    if kind == "email":
        return value.lower()
    if kind == "username":
        return value.lstrip("@")
    if kind == "phone":
        plus = value.startswith("+")
        return ("+" if plus else "") + re.sub(r"\D", "", value)
    if kind == "hash":
        return value.lower()
    return value
