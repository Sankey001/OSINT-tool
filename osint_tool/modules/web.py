"""Website fingerprinting: redirects, headers, technologies, security header
grade, and contact details scraped from the landing page."""

import html
import re
from urllib.parse import urljoin, urlparse

import requests

from .. import net
from . import ModuleError, module

SECURITY_HEADERS = {
    "strict-transport-security": "Forces HTTPS (HSTS)",
    "content-security-policy": "Restricts script/content sources",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "Stops MIME sniffing",
    "referrer-policy": "Limits referrer leakage",
    "permissions-policy": "Restricts browser features",
}

# (name, where, regex) - where is "header:<name>", "html" or "cookie"
TECH_SIGNATURES = [
    ("Cloudflare", "header:server", r"cloudflare"),
    ("Cloudflare", "header:cf-ray", r"."),
    ("nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("Microsoft IIS", "header:server", r"iis"),
    ("LiteSpeed", "header:server", r"litespeed"),
    ("Caddy", "header:server", r"caddy"),
    ("Amazon CloudFront", "header:via", r"cloudfront"),
    ("Amazon S3", "header:server", r"amazons3"),
    ("Fastly", "header:x-served-by", r"cache-"),
    ("Akamai", "header:server", r"akamai"),
    ("Vercel", "header:server", r"vercel"),
    ("Netlify", "header:server", r"netlify"),
    ("GitHub Pages", "header:server", r"github\.com"),
    ("Google Frontend", "header:server", r"google frontend|gws"),
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("Express", "header:x-powered-by", r"express"),
    ("Next.js", "header:x-powered-by", r"next\.js"),
    ("Next.js", "html", r"/_next/static|__NEXT_DATA__"),
    ("Nuxt", "html", r"/_nuxt/|__NUXT__"),
    ("React", "html", r"data-reactroot|react(?:\.production)?\.min\.js"),
    ("Vue.js", "html", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|data-v-[0-9a-f]{8}"),
    ("Angular", "html", r"ng-version=|angular(?:\.min)?\.js"),
    ("Svelte", "html", r"svelte-[a-z0-9]{6}|__sveltekit"),
    ("jQuery", "html", r"jquery[\-.\d]*(?:\.min)?\.js"),
    ("Bootstrap", "html", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Tailwind CSS", "html", r"tailwind"),
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("Drupal", "html", r"drupal-settings-json|/sites/default/files"),
    ("Joomla", "html", r"/media/jui/|joomla"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Wix", "html", r"static\.wixstatic\.com"),
    ("Squarespace", "html", r"static1\.squarespace\.com"),
    ("Webflow", "html", r"webflow\.(?:js|css)|data-wf-page"),
    ("Ghost", "html", r"ghost-(?:sdk|portal)|content=\"Ghost"),
    ("Hugo", "html", r"content=\"Hugo"),
    ("Gatsby", "html", r"___gatsby"),
    ("Google Analytics", "html", r"google-analytics\.com|gtag\(|googletagmanager\.com/gtag"),
    ("Google Tag Manager", "html", r"googletagmanager\.com/gtm"),
    ("Facebook Pixel", "html", r"connect\.facebook\.net/.*/fbevents"),
    ("Hotjar", "html", r"static\.hotjar\.com"),
    ("HubSpot", "html", r"js\.hs-scripts\.com|hs-analytics"),
    ("Intercom", "html", r"widget\.intercom\.io"),
    ("Stripe", "html", r"js\.stripe\.com"),
    ("reCAPTCHA", "html", r"google\.com/recaptcha"),
    ("hCaptcha", "html", r"hcaptcha\.com"),
    ("Cloudflare Turnstile", "html", r"challenges\.cloudflare\.com/turnstile"),
    ("PHP session", "cookie", r"phpsessid"),
    ("Java", "cookie", r"jsessionid"),
    ("ASP.NET session", "cookie", r"asp\.net_sessionid"),
    ("Laravel", "cookie", r"laravel_session"),
    ("Django", "cookie", r"csrftoken|sessionid"),
]

SOCIAL_PATTERNS = {
    "twitter": r"https?://(?:www\.)?(?:twitter|x)\.com/(?!intent|share|home)[A-Za-z0-9_]{1,15}",
    "facebook": r"https?://(?:www\.)?facebook\.com/(?!sharer|share|dialog|plugins)[A-Za-z0-9.\-]+",
    "instagram": r"https?://(?:www\.)?instagram\.com/[A-Za-z0-9_.]+",
    "linkedin": r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in|school)/[A-Za-z0-9_\-%]+",
    "youtube": r"https?://(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)[A-Za-z0-9_\-]+",
    "github": r"https?://(?:www\.)?github\.com/[A-Za-z0-9\-]+",
    "tiktok": r"https?://(?:www\.)?tiktok\.com/@[A-Za-z0-9_.]+",
    "telegram": r"https?://t\.me/[A-Za-z0-9_]+",
    "discord": r"https?://(?:www\.)?discord\.(?:gg|com/invite)/[A-Za-z0-9]+",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"tel:([+\d\s().\-]{7,20})")
ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")


def detect_tech(headers, body, cookies):
    found = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    cookie_blob = " ".join(cookies).lower()
    for name, where, pattern in TECH_SIGNATURES:
        if name in found:
            continue
        if where.startswith("header:"):
            hay = lower_headers.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            hay = cookie_blob
        else:
            hay = body
        if hay and re.search(pattern, hay, re.I):
            found.append(name)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen and gen.group(1) not in found:
        found.append(gen.group(1).strip())
    return found


def grade_security_headers(headers):
    lower = {k.lower() for k in headers}
    present = [h for h in SECURITY_HEADERS if h in lower]
    missing = [h for h in SECURITY_HEADERS if h not in lower]
    score = len(present)
    grade = "A" if score >= 6 else "B" if score >= 5 else "C" if score >= 3 else "D" if score >= 1 else "F"
    return {
        "grade": grade,
        "present": present,
        "missing": [{"header": h, "why": SECURITY_HEADERS[h]} for h in missing],
    }


def extract_contacts(body, domain):
    emails = sorted({
        e.lower() for e in EMAIL_RE.findall(html.unescape(body))
        if not e.lower().endswith(ASSET_EXT) and "example." not in e.lower()
    })
    phones = sorted({p.strip() for p in PHONE_RE.findall(body)})
    social = {}
    for network, pattern in SOCIAL_PATTERNS.items():
        links = sorted({m.rstrip("/") for m in re.findall(pattern, body, re.I)})
        if links:
            social[network] = links[:5]
    return {"emails": emails[:50], "phones": phones[:20], "social": social}


def page_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(" ".join(m.group(1).split()))[:200] if m else None


def meta_description(body):
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)', body, re.I)
    return html.unescape(m.group(1).strip())[:300] if m else None


def fetch(domain):
    last_exc = None
    for scheme in ("https", "http"):
        try:
            return net.get(f"{scheme}://{domain}/", timeout=12, allow_redirects=True)
        except requests.RequestException as exc:
            last_exc = exc
    raise ModuleError(f"Site unreachable: {last_exc}")


def fetch_text(url):
    try:
        r = net.get(url, timeout=8, allow_redirects=True)
        if r.status_code == 200 and "<html" not in r.text[:500].lower():
            return r.text[:5000]
    except requests.RequestException:
        pass
    return None


@module("web", "Website Fingerprint", ["domain"],
        "Redirects, server stack, technologies, security headers and contacts found on the homepage.",
        order=25)
def web(domain):
    if not net.host_is_public(domain):
        raise ModuleError("Refusing to probe a private/internal address")
    resp = fetch(domain)
    body = resp.text[:600_000] if "html" in resp.headers.get("content-type", "") else ""
    cookies = [c.name for c in resp.cookies]
    final_host = urlparse(resp.url).hostname or domain
    robots = fetch_text(urljoin(resp.url, "/robots.txt"))
    security_txt = fetch_text(urljoin(resp.url, "/.well-known/security.txt"))
    disallowed = []
    if robots:
        disallowed = [line.split(":", 1)[1].strip() for line in robots.splitlines()
                      if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()]
    return {
        "url": resp.url,
        "status": resp.status_code,
        "redirects": [{"status": r.status_code, "url": r.url} for r in resp.history]
                     + [{"status": resp.status_code, "url": resp.url}],
        "final_host": final_host,
        "title": page_title(body),
        "description": meta_description(body),
        "server": resp.headers.get("server"),
        "headers": dict(resp.headers),
        "cookies": cookies,
        "technologies": detect_tech(resp.headers, body, cookies),
        "security_headers": grade_security_headers(resp.headers),
        "contacts": extract_contacts(body, domain),
        "robots_disallow": disallowed[:40],
        "security_txt": security_txt,
    }
