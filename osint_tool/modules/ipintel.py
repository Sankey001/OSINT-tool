"""IP address intelligence: geolocation, ASN, reverse DNS and exposed
services (Shodan InternetDB - free, no API key)."""

import ipaddress
import socket

import requests

from .. import net
from . import ModuleError, module
from .dns import resolve


def _require_public(ip):
    if not net.is_public_ip(ip):
        raise ModuleError("Private, reserved or loopback address - nothing public to look up")


def geo_ipwhois(ip):
    data = net.get_json(f"https://ipwho.is/{ip}", timeout=10)
    if not data.get("success", True):
        raise ModuleError(data.get("message", "lookup failed"))
    conn = data.get("connection") or {}
    return {
        "country": data.get("country"), "country_code": data.get("country_code"),
        "region": data.get("region"), "city": data.get("city"), "postal": data.get("postal"),
        "lat": data.get("latitude"), "lon": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "asn": f"AS{conn['asn']}" if conn.get("asn") else None,
        "org": conn.get("org"), "isp": conn.get("isp"), "source": "ipwho.is",
    }


def geo_ipapi(ip):
    data = net.get_json(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,countryCode,regionName,city,zip,lat,lon,"
                          "timezone,isp,org,as,proxy,hosting,mobile"},
        timeout=10,
    )
    if data.get("status") != "success":
        raise ModuleError(data.get("message", "lookup failed"))
    return {
        "country": data.get("country"), "country_code": data.get("countryCode"),
        "region": data.get("regionName"), "city": data.get("city"), "postal": data.get("zip"),
        "lat": data.get("lat"), "lon": data.get("lon"), "timezone": data.get("timezone"),
        "asn": (data.get("as") or "").split(" ")[0] or None,
        "org": data.get("org"), "isp": data.get("isp"),
        "proxy": data.get("proxy"), "hosting": data.get("hosting"), "mobile": data.get("mobile"),
        "source": "ip-api.com",
    }


@module("geoip", "Geolocation & Network", ["ip"],
        "Approximate location, ISP and ASN, plotted on a map.", order=10)
def geoip(ip):
    _require_public(ip)
    errors = []
    for fn in (geo_ipwhois, geo_ipapi):
        try:
            return fn(ip)
        except Exception as exc:
            errors.append(f"{fn.__name__}: {exc}")
    raise ModuleError("; ".join(errors))


def reverse_pointer(ip):
    return ipaddress.ip_address(ip).reverse_pointer


@module("rdns", "Reverse DNS", ["ip"], "PTR records and forward-confirmation.", order=12)
def rdns(ip):
    _require_public(ip)
    names = []
    try:
        names = resolve(reverse_pointer(ip), "PTR")
    except Exception:
        pass
    if not names:
        try:
            names = [socket.gethostbyaddr(ip)[0]]
        except (socket.herror, socket.gaierror, OSError):
            names = []
    names = [n.rstrip(".") for n in names]
    confirmed = {}
    for name in names:
        rtype = "AAAA" if ":" in ip else "A"
        try:
            confirmed[name] = ip in resolve(name, rtype)
        except Exception:
            confirmed[name] = None
    return {"ptr": names, "forward_confirmed": confirmed}


@module("exposure", "Open Ports & CVEs", ["ip"],
        "Exposed ports, software (CPEs) and known vulnerabilities from Shodan InternetDB.", order=14)
def exposure(ip):
    _require_public(ip)
    try:
        resp = net.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
    except requests.RequestException as exc:
        raise ModuleError(f"InternetDB unreachable: {exc}")
    if resp.status_code == 404:
        return {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": [],
                "note": "No open services observed by Shodan"}
    resp.raise_for_status()
    data = resp.json()
    return {k: data.get(k, []) for k in ("ports", "hostnames", "cpes", "tags", "vulns")}
