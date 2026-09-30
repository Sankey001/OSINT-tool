"""Passive subdomain enumeration from Certificate Transparency logs."""

from .. import net
from . import ModuleError, module

MAX_RESULTS = 500


def from_crtsh(domain):
    data = net.get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        timeout=30)
    names = set()
    for row in data:
        for name in (row.get("name_value") or "").splitlines():
            names.add(name)
    return names


def from_hackertarget(domain):
    resp = net.get("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=20)
    resp.raise_for_status()
    if "error" in resp.text.lower()[:100] or "API count exceeded" in resp.text:
        raise ModuleError(resp.text.strip()[:120])
    return {line.split(",")[0] for line in resp.text.splitlines() if line}


def clean(names, domain):
    out = set()
    for name in names:
        name = name.strip().lower().lstrip("*.").rstrip(".")
        if name and (name == domain or name.endswith("." + domain)) and " " not in name:
            out.add(name)
    return sorted(out, key=lambda n: (n.count("."), n))


@module("subdomains", "Subdomains", ["domain"],
        "Passive enumeration from Certificate Transparency logs (crt.sh), with a HackerTarget fallback.",
        order=30)
def subdomains(domain):
    sources, errors, names = [], [], set()
    for label, fn in (("crt.sh", from_crtsh), ("hackertarget", from_hackertarget)):
        try:
            names |= fn(domain)
            sources.append(label)
            if names:
                break
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    if not sources:
        raise ModuleError("; ".join(errors))
    found = [n for n in clean(names, domain) if n != domain]
    return {
        "count": len(found),
        "subdomains": found[:MAX_RESULTS],
        "truncated": len(found) > MAX_RESULTS,
        "sources": sources,
    }
