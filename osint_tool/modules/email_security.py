"""SPF / DMARC / MTA-STS posture - tells you how spoofable a domain is."""

from concurrent.futures import ThreadPoolExecutor

from . import module
from .dns import resolve


def analyze_spf(txt_records):
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "grade": "bad", "note": "No SPF record - anyone can send as this domain"}
    record = spf[0]
    if len(spf) > 1:
        return {"present": True, "record": record, "grade": "bad",
                "note": "Multiple SPF records (invalid per RFC 7208)"}
    tokens = record.split()
    policy = tokens[-1] if tokens else ""
    notes = {
        "-all": ("good", "Hard fail - unauthorized senders rejected"),
        "~all": ("warn", "Soft fail - unauthorized mail usually marked as spam"),
        "?all": ("bad", "Neutral - SPF provides no protection"),
        "+all": ("bad", "Pass all - anyone may send as this domain"),
    }
    grade, note = notes.get(policy, ("warn", "No terminating 'all' mechanism"))
    includes = [t.split(":", 1)[1] for t in tokens if t.startswith("include:")]
    return {"present": True, "record": record, "policy": policy, "includes": includes,
            "grade": grade, "note": note}


def analyze_dmarc(txt_records):
    dmarc = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return {"present": False, "grade": "bad", "note": "No DMARC record"}
    record = dmarc[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "none").lower()
    grade = {"reject": "good", "quarantine": "good", "none": "warn"}.get(policy, "warn")
    note = {
        "reject": "Spoofed mail is rejected",
        "quarantine": "Spoofed mail is quarantined",
        "none": "Monitoring only - spoofed mail is still delivered",
    }.get(policy, "Unknown policy")
    return {"present": True, "record": record, "policy": policy, "pct": tags.get("pct", "100"),
            "rua": tags.get("rua"), "grade": grade, "note": note}


def infer_mail_provider(txt_records, spf):
    joined = " ".join(txt_records).lower() + " " + " ".join(spf.get("includes", []))
    providers = {
        "google.com": "Google Workspace", "outlook.com": "Microsoft 365",
        "zoho": "Zoho Mail", "mailgun": "Mailgun", "sendgrid": "SendGrid",
        "amazonses": "Amazon SES", "mandrillapp": "Mailchimp/Mandrill",
        "protonmail": "Proton Mail", "mimecast": "Mimecast", "pphosted": "Proofpoint",
        "salesforce": "Salesforce", "hubspot": "HubSpot", "zendesk": "Zendesk",
    }
    return sorted({name for key, name in providers.items() if key in joined})


def site_verifications(txt_records):
    markers = {
        "google-site-verification": "Google", "facebook-domain-verification": "Facebook",
        "ms=": "Microsoft", "apple-domain-verification": "Apple",
        "atlassian-domain-verification": "Atlassian", "docusign": "DocuSign",
        "stripe-verification": "Stripe", "globalsign": "GlobalSign", "adobe-idp-site-verification": "Adobe",
        "zoom-domain-verification": "Zoom", "slack-domain-verification": "Slack",
        "openai-domain-verification": "OpenAI", "dropbox-domain-verification": "Dropbox",
        "_github-challenge": "GitHub", "have-i-been-pwned-verification": "HIBP",
    }
    found = set()
    for rec in txt_records:
        low = rec.lower()
        for key, name in markers.items():
            if low.startswith(key):
                found.add(name)
    return sorted(found)


@module("email_security", "Email Security", ["domain"],
        "SPF, DMARC and MTA-STS - how easy is it to spoof this domain?", order=20)
def email_security(domain):
    lookups = {
        "root": domain,
        "dmarc": f"_dmarc.{domain}",
        "mta_sts": f"_mta-sts.{domain}",
    }
    with ThreadPoolExecutor(max_workers=3) as pool:
        res = dict(zip(lookups, pool.map(lambda n: resolve(n, "TXT"), lookups.values())))
    spf = analyze_spf(res["root"])
    dmarc = analyze_dmarc(res["dmarc"])
    score = {"good": 2, "warn": 1, "bad": 0}
    total = score[spf["grade"]] + score[dmarc["grade"]]
    spoofable = "low" if total >= 4 else "medium" if total >= 2 else "high"
    return {
        "spf": spf,
        "dmarc": dmarc,
        "mta_sts": bool(res["mta_sts"]),
        "spoofing_risk": spoofable,
        "mail_services": infer_mail_provider(res["root"], spf),
        "verified_services": site_verifications(res["root"]),
    }
