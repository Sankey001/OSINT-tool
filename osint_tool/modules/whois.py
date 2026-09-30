"""Registration data via RDAP - the structured JSON successor to WHOIS."""

from datetime import datetime, timezone

import requests

from .. import net
from . import ModuleError, module

RDAP_BASE = "https://rdap.org"


def _vcard_field(entity, key):
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if item and item[0] == key:
            val = item[3]
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val if v)
            return val or None
    return None


def _entities(entities, depth=0):
    out = []
    for ent in entities or []:
        info = {
            "roles": ent.get("roles", []),
            "handle": ent.get("handle"),
            "name": _vcard_field(ent, "fn") or _vcard_field(ent, "org"),
            "email": _vcard_field(ent, "email"),
            "phone": _vcard_field(ent, "tel"),
            "address": _vcard_field(ent, "adr"),
        }
        for pid in ent.get("publicIds") or []:
            if pid.get("type", "").lower().startswith("iana"):
                info["iana_id"] = pid.get("identifier")
        out.append({k: v for k, v in info.items() if v})
        if depth < 2:
            out.extend(_entities(ent.get("entities"), depth + 1))
    return out


def _events(data):
    events = {}
    for ev in data.get("events") or []:
        events[ev.get("eventAction", "?")] = ev.get("eventDate")
    return events


def age_days(iso):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return (datetime.now(timezone.utc) - dt).days


def parse_domain(data):
    events = _events(data)
    entities = _entities(data.get("entities"))
    registrar = next((e for e in entities if "registrar" in e.get("roles", [])), {})
    registrant = next((e for e in entities if "registrant" in e.get("roles", [])), {})
    created = events.get("registration")
    expires = events.get("expiration")
    exp_days = age_days(expires)
    return {
        "domain": (data.get("ldhName") or "").lower(),
        "registrar": registrar.get("name"),
        "registrar_iana_id": registrar.get("iana_id"),
        "registrant": registrant or None,
        "created": created,
        "updated": events.get("last changed"),
        "expires": expires,
        "age_days": age_days(created),
        "expires_in_days": -exp_days if exp_days is not None else None,
        "status": data.get("status", []),
        "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers") or []],
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
        "contacts": entities,
    }


def parse_ip(data):
    events = _events(data)
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "range": f"{data.get('startAddress')} - {data.get('endAddress')}",
        "cidr": [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                 for c in data.get("cidr0_cidrs") or []],
        "country": data.get("country"),
        "type": data.get("type"),
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "contacts": _entities(data.get("entities")),
    }


def rdap(kind, value):
    try:
        resp = net.get(f"{RDAP_BASE}/{kind}/{value}",
                       headers={"Accept": "application/rdap+json"}, timeout=15)
    except requests.RequestException as exc:
        raise ModuleError(f"RDAP request failed: {exc}")
    if resp.status_code == 404:
        raise ModuleError("No RDAP record found (unregistered, or TLD without RDAP)")
    resp.raise_for_status()
    return resp.json()


@module("whois", "WHOIS / RDAP", ["domain", "ip"],
        "Registrar, dates, nameservers and contacts from RDAP.", order=15)
def whois(target):
    if ":" in target or target.replace(".", "").isdigit():
        return {"kind": "ip", **parse_ip(rdap("ip", target))}
    return {"kind": "domain", **parse_domain(rdap("domain", target))}
