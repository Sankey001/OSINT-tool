"""Search-engine dorks and pivot links to external OSINT services.

These don't call anything - they build ready-to-click queries tailored to
the target type, grouped into categories."""

from urllib.parse import quote_plus

from . import module

ENGINES = {
    "google": "https://www.google.com/search?q={}",
    "bing": "https://www.bing.com/search?q={}",
    "duckduckgo": "https://duckduckgo.com/?q={}",
    "yandex": "https://yandex.com/search/?text={}",
}

SOCIAL_SITES = [
    "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com", "reddit.com",
    "tiktok.com", "youtube.com", "github.com", "medium.com", "pinterest.com", "quora.com",
    "t.me", "vk.com", "tumblr.com", "twitch.tv", "stackoverflow.com", "soundcloud.com",
]

FILETYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "sql",
             "log", "env", "json", "xml", "bak", "conf"]


def dork(label, query):
    return {"label": label, "query": query,
            "links": {name: tpl.format(quote_plus(query)) for name, tpl in ENGINES.items()}}


def domain_dorks(d):
    return {
        "Recon": [
            dork("All indexed pages", f"site:{d}"),
            dork("Subdomains (exclude www)", f"site:*.{d} -site:www.{d}"),
            dork("Mentions elsewhere", f"\"{d}\" -site:{d}"),
            dork("Login & admin pages", f"site:{d} inurl:login | inurl:admin | inurl:signin | inurl:dashboard"),
            dork("Pages with parameters", f"site:{d} inurl:? | inurl:= "),
        ],
        "Exposed files": [
            dork("Documents", f"site:{d} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx"),
            dork("Config & env files", f"site:{d} ext:env | ext:ini | ext:conf | ext:cfg | ext:yml | ext:yaml"),
            dork("Database dumps & backups", f"site:{d} ext:sql | ext:db | ext:bak | ext:backup | ext:old"),
            dork("Log files", f"site:{d} ext:log"),
            dork("Directory listings", f"site:{d} intitle:\"index of\""),
        ],
        "Leaks & code": [
            dork("Paste sites", f"\"{d}\" site:pastebin.com | site:paste.ee | site:ghostbin.com | site:rentry.co"),
            dork("Code repositories", f"\"{d}\" site:github.com | site:gitlab.com | site:bitbucket.org"),
            dork("Error messages", f"site:{d} \"sql syntax\" | \"warning: mysql\" | \"stack trace\" | \"exception\""),
            dork("Cloud buckets", f"\"{d}\" site:s3.amazonaws.com | site:blob.core.windows.net | site:storage.googleapis.com"),
        ],
        "People": [
            dork("Employees on LinkedIn", f"site:linkedin.com/in \"{d.split('.')[0]}\""),
            dork("Email addresses", f"\"@{d}\" -site:{d}"),
        ],
    }


def person_dorks(q):
    quoted = f"\"{q}\""
    return {
        "Social profiles": [dork(site, f"site:{site} {quoted}") for site in SOCIAL_SITES],
        "Documents": [dork(ft.upper(), f"{quoted} filetype:{ft}") for ft in FILETYPES[:9]],
        "Records": [
            dork("Resumes / CVs", f"{quoted} (resume OR cv OR \"curriculum vitae\") filetype:pdf"),
            dork("News", f"{quoted} site:news.google.com | inurl:news"),
            dork("Contact info", f"{quoted} (email OR phone OR contact OR \"@gmail.com\")"),
            dork("Paste sites", f"{quoted} site:pastebin.com | site:paste.ee | site:rentry.co"),
            dork("Forums", f"{quoted} inurl:forum | inurl:thread | inurl:viewtopic"),
        ],
    }


def username_dorks(u):
    return {
        "Mentions": [
            dork("Exact handle", f"\"{u}\""),
            dork("Handle with @", f"\"@{u}\""),
            dork("In URLs", f"inurl:{u}"),
            dork("Paste sites", f"\"{u}\" site:pastebin.com | site:paste.ee | site:rentry.co"),
            dork("Forums", f"\"{u}\" inurl:forum | inurl:member | inurl:profile"),
        ],
        "Social profiles": [dork(site, f"site:{site} \"{u}\"") for site in SOCIAL_SITES],
    }


def email_dorks(e):
    return {
        "Mentions": [
            dork("Exact address", f"\"{e}\""),
            dork("In documents", f"\"{e}\" ext:pdf | ext:doc | ext:docx | ext:xls | ext:csv | ext:txt"),
            dork("Paste sites & leaks", f"\"{e}\" site:pastebin.com | site:paste.ee | site:rentry.co"),
            dork("Code repositories", f"\"{e}\" site:github.com | site:gitlab.com"),
            dork("Social profiles", f"\"{e}\" site:linkedin.com | site:twitter.com | site:facebook.com"),
        ],
    }


def phone_dorks(p):
    digits = p.lstrip("+")
    return {
        "Mentions": [
            dork("Exact number", f"\"{p}\" | \"{digits}\""),
            dork("Business listings", f"\"{digits}\" site:yelp.com | site:yellowpages.com | site:facebook.com"),
            dork("Classifieds", f"\"{digits}\" site:craigslist.org | site:olx.com | site:gumtree.com"),
            dork("Documents", f"\"{digits}\" ext:pdf | ext:xls | ext:xlsx | ext:csv"),
        ],
    }


def ip_dorks(ip):
    return {
        "Mentions": [
            dork("Exact IP", f"\"{ip}\""),
            dork("Abuse reports", f"\"{ip}\" (spam OR abuse OR malware OR attack OR botnet)"),
            dork("Paste sites", f"\"{ip}\" site:pastebin.com | site:paste.ee"),
        ],
    }


def tools(kind, t):
    q = quote_plus(t)
    common = {
        "domain": [
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{t}"),
            ("Shodan", f"https://www.shodan.io/search?query=hostname%3A{q}"),
            ("Censys", f"https://search.censys.io/search?resource=hosts&q={q}"),
            ("SecurityTrails", f"https://securitytrails.com/domain/{t}/dns"),
            ("DNSDumpster", "https://dnsdumpster.com/"),
            ("URLScan", f"https://urlscan.io/search/#domain%3A{q}"),
            ("BuiltWith", f"https://builtwith.com/{t}"),
            ("crt.sh", f"https://crt.sh/?q=%25.{t}"),
            ("Wayback", f"https://web.archive.org/web/*/{t}*"),
            ("ViewDNS", f"https://viewdns.info/reverseip/?host={t}&t=1"),
            ("Hunter.io", f"https://hunter.io/search/{t}"),
            ("Google Safe Browsing", f"https://transparencyreport.google.com/safe-browsing/search?url={t}"),
        ],
        "ip": [
            ("Shodan", f"https://www.shodan.io/host/{t}"),
            ("Censys", f"https://search.censys.io/hosts/{t}"),
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{t}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{t}"),
            ("GreyNoise", f"https://viz.greynoise.io/ip/{t}"),
            ("AlienVault OTX", f"https://otx.alienvault.com/indicator/ip/{t}"),
            ("IPinfo", f"https://ipinfo.io/{t}"),
            ("BGP.he.net", f"https://bgp.he.net/ip/{t}"),
            ("ViewDNS reverse IP", f"https://viewdns.info/reverseip/?host={t}&t=1"),
        ],
        "email": [
            ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{q}"),
            ("Epieos", "https://epieos.com/"),
            ("Hunter verify", f"https://hunter.io/email-verifier/{q}"),
            ("IntelX", f"https://intelx.io/?s={q}"),
            ("DeHashed", f"https://dehashed.com/search?query={q}"),
        ],
        "username": [
            ("WhatsMyName", f"https://whatsmyname.app/?q={q}"),
            ("Namechk", f"https://namechk.com/"),
            ("IntelX", f"https://intelx.io/?s={q}"),
        ],
        "phone": [
            ("WhatsApp", f"https://wa.me/{t.lstrip('+')}"),
            ("Telegram", f"https://t.me/{t}"),
            ("Truecaller", f"https://www.truecaller.com/search/global/{t.lstrip('+')}"),
            ("Sync.me", f"https://sync.me/search/?number={q}"),
            ("NumLookup", f"https://www.numlookup.com/"),
        ],
        "name": [
            ("Google Images", f"https://www.google.com/search?tbm=isch&q={q}"),
            ("Pipl", "https://pipl.com/"),
            ("That's Them", "https://thatsthem.com/"),
            ("Google Maps", f"https://www.google.com/maps/search/{q}"),
            ("OpenCorporates", f"https://opencorporates.com/companies?q={q}"),
            ("LinkedIn search", f"https://www.linkedin.com/search/results/all/?keywords={q}"),
        ],
    }
    return [{"name": n, "url": u} for n, u in common.get(kind, [])]


BUILDERS = {
    "domain": domain_dorks, "name": person_dorks, "username": username_dorks,
    "email": email_dorks, "phone": phone_dorks, "ip": ip_dorks,
}


def build(kind, target):
    groups = BUILDERS[kind](target)
    return {"groups": groups, "count": sum(len(v) for v in groups.values()),
            "tools": tools(kind, target)}


def _register(kind):
    @module(f"dorks_{kind}", "Search Dorks & Pivots", [kind],
            "Tailored search-engine dorks and one-click links to external OSINT services.", order=90)
    def _run(target):
        return build(kind, target)


for _kind in BUILDERS:
    _register(_kind)
