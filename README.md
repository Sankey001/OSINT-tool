# Recon: OSINT Toolkit

Recon is an open-source intelligence toolkit that runs in your browser. Type a **domain, IP address, email, username, phone number, hash or name**. Recon works out what it is and runs every relevant lookup in parallel. Each result appears on its own card as soon as it finishes.

It replaces the original Tkinter app, which is kept in [`legacy/osint_tkinter.py`](legacy/osint_tkinter.py). That app only opened Google searches in new tabs. Recon collects the data itself and shows it in one dashboard.

## What it looks up

| Target | Modules |
| --- | --- |
| **Domain** | DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA) · RDAP/WHOIS (registrar, age, expiry, contacts) · SPF / DMARC / MTA-STS spoofing-risk grade · website fingerprint (redirects, tech stack, security-header grade, emails & social links on the page, robots.txt, security.txt) · subdomains from Certificate Transparency · TLS certificate · Wayback Machine history |
| **IP** | Geolocation on a map, ASN, ISP, proxy/hosting flags · reverse DNS with forward confirmation · open ports, CPEs and CVEs (Shodan InternetDB) · RDAP network ownership |
| **Username** | Account checks on 47 platforms (GitHub, GitLab, Reddit, Mastodon, Bluesky, Telegram, Steam, Chess.com, PyPI, npm, Docker Hub, and more), with direct profile links |
| **Email** | MX / deliverability · mail provider · free, disposable and role-account detection · Gravatar profile · username check on the local part |
| **Phone** | Validity, country, region, carrier, line type, time zones (libphonenumber) |
| **Hash** | Algorithm identification plus VirusTotal, MalwareBazaar and other lookups |
| **Everything** | Search dorks for your target, one click away in Google, Bing, DuckDuckGo or Yandex, plus pivot links to 40+ external services (Shodan, Censys, HIBP, AbuseIPDB, …) |

No API keys are required. Every data source is free and public.

### UI features
- Detects the target type as you type, and you can override it with one click
- Results stream in: a live progress bar and status on every card, and you can re-run a single module
- **Pivoting:** click any subdomain, IP, nameserver, email or username in the results to scan it
- Scan history in the sidebar (stored only in your browser)
- Export results as JSON or Markdown, or print to PDF
- Dark and light themes, a mobile-friendly layout, and a `/` shortcut to focus the search box
- Shareable URLs (`/?q=example.com`)

## Install and run

```bash
git clone https://github.com/Sankey001/OSINT-tool.git
cd OSINT-tool
pip install -r requirements.txt
python -m osint_tool
```

The UI opens at <http://127.0.0.1:5000>. Options: `python -m osint_tool serve --port 8080 --no-browser`.

### Command line

```bash
python -m osint_tool scan example.com
python -m osint_tool scan torvalds --type username
python -m osint_tool scan 1.1.1.1 --only geoip,exposure --json > report.json
```

## Project layout

```
osint_tool/
  app.py          Flask server + JSON API (/api/detect, /api/run/<module>)
  detect.py       target-type detection
  net.py          shared HTTP session and private-address guard
  modules/        one file per lookup, each registered with @module(...)
  static/         the single-page UI (HTML/CSS/JS)
tests/            pytest suite (network calls are mocked)
legacy/           the original Tkinter tool
```

### Adding a module

```python
from . import module

@module("my_lookup", "My Lookup", ["domain"], "What it does.", order=60)
def my_lookup(domain):
    return {"anything": "JSON-serializable"}
```

Import the file in `osint_tool/modules/__init__.py`. The UI shows a generic JSON view for it until you add a renderer in `static/app.js` (`R.my_lookup = (data) => ...`).

## Tests

```bash
pip install pytest
python -m pytest
```

## Disclaimer

This tool is for education and lawful research only, such as investigating your own assets, authorized security assessments and journalism. Follow the laws where you live and each website's terms of service. The web and TLS modules refuse to probe private or internal addresses, and the server listens only on localhost by default.

## Credits

Originally created by Sanket Subhralok Mohapatra. Licensed under MIT (see `LICENSE`).
