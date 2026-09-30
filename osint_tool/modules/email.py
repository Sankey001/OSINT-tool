"""Email address analysis."""

import hashlib

import requests

from .. import net
from . import module
from .dns import parse_mx, resolve

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "gmx.com",
    "gmx.de", "gmx.net", "web.de", "mail.com", "yandex.com", "yandex.ru", "mail.ru",
    "proton.me", "protonmail.com", "pm.me", "zoho.com", "tutanota.com", "tuta.io",
    "fastmail.com", "hey.com", "qq.com", "163.com", "126.com", "rediffmail.com",
}

DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "guerrillamail.net",
    "sharklasers.com", "yopmail.com", "temp-mail.org", "tempmail.com", "throwawaymail.com",
    "trashmail.com", "getnada.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
    "mintemail.com", "mohmal.com", "emailondeck.com", "burnermail.io", "tempr.email",
    "discard.email", "spamgourmet.com", "mailnesia.com", "moakt.com", "tmpmail.org",
    "1secmail.com", "emailfake.com", "mytemp.email", "inboxkitten.com",
}

ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "contact", "support", "help", "sales", "billing",
    "abuse", "postmaster", "hostmaster", "webmaster", "security", "noreply", "no-reply",
    "hello", "team", "office", "hr", "jobs", "careers", "press", "media", "marketing",
}

MX_PROVIDERS = {
    "google.com": "Google", "googlemail.com": "Google", "outlook.com": "Microsoft",
    "protection.outlook.com": "Microsoft 365", "yahoodns.net": "Yahoo", "zoho": "Zoho",
    "protonmail.ch": "Proton", "mimecast": "Mimecast", "pphosted.com": "Proofpoint",
    "icloud.com": "Apple iCloud", "messagingengine.com": "Fastmail", "mailgun.org": "Mailgun",
    "secureserver.net": "GoDaddy", "yandex": "Yandex", "mail.ru": "Mail.ru",
}


def gravatar(email):
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()  # noqa: S324 - Gravatar's scheme
    info = {"hash": digest, "exists": False, "avatar": f"https://www.gravatar.com/avatar/{digest}?s=200&d=404"}
    try:
        resp = net.get(f"https://en.gravatar.com/{digest}.json", timeout=8)
    except requests.RequestException:
        info["exists"] = None
        return info
    if resp.status_code == 200:
        try:
            entry = resp.json()["entry"][0]
        except (ValueError, KeyError, IndexError):
            entry = {}
        info.update({
            "exists": True,
            "profile_url": entry.get("profileUrl"),
            "display_name": entry.get("displayName"),
            "username": entry.get("preferredUsername"),
            "location": entry.get("currentLocation"),
            "about": entry.get("aboutMe"),
            "accounts": [{"name": a.get("shortname"), "url": a.get("url")}
                         for a in entry.get("accounts", [])],
        })
    return info


@module("email", "Email Analysis", ["email"],
        "Deliverability (MX), provider, disposable/role detection and Gravatar profile.", order=5)
def email(address):
    local, _, domain = address.partition("@")
    try:
        mx = parse_mx(resolve(domain, "MX"))
        mx_error = None
    except Exception as exc:
        mx, mx_error = [], str(exc)
    hosts = " ".join(r["host"] for r in mx).lower()
    provider = next((name for key, name in MX_PROVIDERS.items() if key in hosts), None)
    base_local = local.split("+", 1)[0]
    return {
        "local_part": local,
        "domain": domain,
        "mx": mx,
        "mx_error": mx_error,
        "can_receive_mail": bool(mx) if mx_error is None else None,
        "provider": provider,
        "free_provider": domain in FREE_PROVIDERS,
        "disposable": domain in DISPOSABLE,
        "role_account": base_local.lower() in ROLE_ACCOUNTS,
        "plus_addressing": "+" in local,
        "normalized": f"{base_local.replace('.', '') if domain in ('gmail.com', 'googlemail.com') else base_local}@{domain}",
        "gravatar": gravatar(address),
    }
