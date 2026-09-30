"""DNS lookups over DNS-over-HTTPS (no dnspython needed, works behind
restrictive resolvers)."""

from concurrent.futures import ThreadPoolExecutor

from .. import net
from . import ModuleError, module

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
TYPE_CODES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 257: "CAA"}

RESOLVERS = [
    ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
    ("https://dns.google/resolve", {}),
]


def resolve(name, rtype):
    """Return a list of answer strings for ``name``/``rtype``.
    Tries each DoH resolver in turn. NXDOMAIN yields an empty list."""
    last_exc = None
    for url, headers in RESOLVERS:
        try:
            data = net.get_json(url, params={"name": name, "type": rtype},
                                headers=headers, timeout=8)
        except Exception as exc:
            last_exc = exc
            continue
        answers = []
        for ans in data.get("Answer") or []:
            if TYPE_CODES.get(ans.get("type")) != rtype:
                continue
            value = ans.get("data", "")
            if rtype == "TXT":
                value = _join_txt(value)
            answers.append(value.rstrip(".") if rtype in ("CNAME", "NS", "PTR") else value)
        return answers
    raise ModuleError(f"All DNS-over-HTTPS resolvers failed ({last_exc})")


def _join_txt(value):
    # "v=spf1 ... " "more" -> v=spf1 ... more
    parts = value.split('" "')
    return "".join(p.strip('"') for p in parts)


def parse_mx(values):
    out = []
    for v in values:
        pref, _, host = v.partition(" ")
        try:
            out.append({"priority": int(pref), "host": host.rstrip(".")})
        except ValueError:
            out.append({"priority": None, "host": v.rstrip(".")})
    return sorted(out, key=lambda r: (r["priority"] is None, r["priority"]))


@module("dns", "DNS Records", ["domain"],
        "A, AAAA, MX, NS, TXT, SOA, CNAME and CAA records via DNS-over-HTTPS.", order=10)
def dns_records(domain):
    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as pool:
        results = dict(zip(RECORD_TYPES, pool.map(lambda t: _safe(domain, t), RECORD_TYPES)))
    if all(isinstance(v, Exception) for v in results.values()):
        raise ModuleError(str(results["A"]))
    records = {t: ([] if isinstance(v, Exception) else v) for t, v in results.items()}
    records["MX"] = parse_mx(records["MX"])
    total = sum(len(v) for v in records.values())
    if total == 0:
        raise ModuleError("No DNS records found - the domain may not exist")
    return {"records": records, "count": total}


def _safe(domain, rtype):
    try:
        return resolve(domain, rtype)
    except Exception as exc:
        return exc
