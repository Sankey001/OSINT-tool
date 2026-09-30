"""Internet Archive history for a domain."""

from collections import Counter

from .. import net
from . import ModuleError, module


def _fmt(ts):
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if ts and len(ts) >= 8 else ts


@module("wayback", "Wayback Machine", ["domain"],
        "Archive coverage over time - first/last capture and yearly activity.", order=40)
def wayback(domain):
    rows = net.get_json(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": domain, "output": "json", "fl": "timestamp,original,statuscode",
                "collapse": "timestamp:6", "limit": 5000},
        timeout=30,
    )
    if not rows or len(rows) < 2:
        raise ModuleError("No archived captures found")
    captures = rows[1:]
    per_year = Counter(r[0][:4] for r in captures)
    first, last = captures[0], captures[-1]
    link = lambda r: f"https://web.archive.org/web/{r[0]}/{r[1]}"  # noqa: E731
    return {
        "months_with_captures": len(captures),
        "first": {"date": _fmt(first[0]), "url": link(first)},
        "last": {"date": _fmt(last[0]), "url": link(last)},
        "per_year": dict(sorted(per_year.items())),
        "calendar": f"https://web.archive.org/web/*/{domain}*",
    }
