import pytest

from osint_tool.app import create_app
from osint_tool.detect import normalize
from osint_tool.modules import dns, email_security, hashid, modules_for, run_module, subdomains, username, web, whois


@pytest.mark.parametrize("raw,expected", [
    ("example.com", ("domain", "example.com")),
    ("https://Sub.Example.com/path?x=1", ("domain", "sub.example.com")),
    ("8.8.8.8", ("ip", "8.8.8.8")),
    ("[2001:db8::1]", ("ip", "2001:db8::1")),
    ("Jane.Doe@Corp.com", ("email", "jane.doe@corp.com")),
    ("@torvalds", ("username", "torvalds")),
    ("+44 20 7946 0958", ("phone", "+442079460958")),
    ("D41D8CD98F00B204E9800998ECF8427E", ("hash", "d41d8cd98f00b204e9800998ecf8427e")),
    ("Ada  Lovelace", ("name", "Ada Lovelace")),
])
def test_detect(raw, expected):
    assert normalize(raw) == expected


def test_detect_forced_and_empty():
    assert normalize("john.doe", "username") == ("username", "john.doe")
    with pytest.raises(ValueError):
        normalize("   ")


def test_every_type_has_modules():
    for kind in ("domain", "ip", "email", "username", "phone", "hash", "name"):
        assert modules_for(kind), kind


def test_run_module_captures_errors(monkeypatch):
    def boom(*_):
        raise RuntimeError("nope")
    monkeypatch.setattr(dns, "resolve", boom)
    res = run_module("dns", "example.com")
    assert res["ok"] is False and "nope" in res["error"]


def test_dns_parsing(monkeypatch):
    fake = {"Answer": [
        {"type": 15, "data": "20 alt.mx.example.com."},
        {"type": 15, "data": "10 mx.example.com."},
        {"type": 16, "data": '"v=spf1 include:_spf.google.com" " -all"'},
    ]}
    monkeypatch.setattr(dns.net, "get_json", lambda *a, **k: fake)
    assert dns.parse_mx(dns.resolve("example.com", "MX"))[0] == {"priority": 10, "host": "mx.example.com"}
    assert dns.resolve("example.com", "TXT") == ["v=spf1 include:_spf.google.com -all"]


def test_spf_dmarc_grading():
    spf = email_security.analyze_spf(["v=spf1 include:_spf.google.com -all"])
    assert spf["grade"] == "good" and spf["includes"] == ["_spf.google.com"]
    assert email_security.analyze_spf([])["grade"] == "bad"
    assert email_security.analyze_dmarc(["v=DMARC1; p=none; rua=mailto:x@y.z"])["grade"] == "warn"
    assert email_security.analyze_dmarc(["v=DMARC1; p=reject"])["grade"] == "good"


def test_rdap_domain_parse():
    data = {
        "ldhName": "EXAMPLE.COM",
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2999-08-13T04:00:00Z"}],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        "status": ["client delete prohibited"],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-IANA"]]],
                      "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]}],
    }
    out = whois.parse_domain(data)
    assert out["registrar"] == "RESERVED-IANA"
    assert out["registrar_iana_id"] == "376"
    assert out["nameservers"] == ["a.iana-servers.net"]
    assert out["age_days"] > 10000 and out["expires_in_days"] > 0


def test_subdomain_cleaning():
    names = {"*.example.com", "www.example.com", "a.b.example.com", "evil.com", "EXAMPLE.com", "x.example.com."}
    assert subdomains.clean(names, "example.com") == ["example.com", "www.example.com", "x.example.com", "a.b.example.com"]


@pytest.mark.parametrize("check,code,body,status", [
    ("status", 200, "", "found"),
    ("status", 404, "", "not_found"),
    ("status", 429, "", "error"),
    ("absent:[]", 200, "[ ]", "not_found"),
    ("absent:[]", 200, '[{"id":1,"tags":[]}]', "found"),
    ("absent:null", 200, "null", "not_found"),
    ("present:tgme_page_title", 200, "<div class=tgme_page_title>", "found"),
    ("present:tgme_page_title", 200, "<div>nothing</div>", "not_found"),
])
def test_username_interpret(check, code, body, status):
    assert username.interpret(check, code, body)["status"] == status


def test_web_helpers():
    body = ('<html><head><title> Hello &amp; welcome </title><meta name="generator" content="WordPress 6.5">'
            '<script src="/wp-content/x.js"></script></head><body>mail us: team@corp.com '
            '<a href="https://twitter.com/corp">t</a> <img src="logo@2x.png"></body></html>')
    assert web.page_title(body) == "Hello & welcome"
    tech = web.detect_tech({"Server": "cloudflare"}, body, [])
    assert "WordPress" in tech and "Cloudflare" in tech
    contacts = web.extract_contacts(body, "corp.com")
    assert contacts["emails"] == ["team@corp.com"]
    assert contacts["social"]["twitter"] == ["https://twitter.com/corp"]
    assert web.grade_security_headers({"Strict-Transport-Security": "x"})["grade"] == "D"


def test_hash_and_dorks():
    assert hashid.identify("a" * 64)["likely"] == "SHA-256"
    res = run_module("dorks_domain", "example.com")
    assert res["ok"] and res["data"]["count"] > 10
    assert all(set(d["links"]) == {"google", "bing", "duckduckgo", "yandex"}
               for group in res["data"]["groups"].values() for d in group)


def test_private_ip_refused():
    res = run_module("geoip", "192.168.1.1")
    assert not res["ok"] and "Private" in res["error"]


def test_api_routes():
    client = create_app().test_client()
    assert client.get("/").status_code == 200
    d = client.get("/api/detect?q=example.com").get_json()
    assert d["type"] == "domain" and any(m["name"] == "dns" for m in d["modules"])
    assert client.get("/api/detect?q=").status_code == 400
    assert client.get("/api/run/nope?q=x").status_code == 404
    r = client.get("/api/run/hash?q=" + "b" * 40).get_json()
    assert r["ok"] and r["data"]["likely"] == "SHA-1"
    assert client.get("/static/app.js").status_code == 200
