"""Username enumeration across public platforms.

Each site declares how existence is detected:
  status      - HTTP 200 means found, 404/410 means not found
  absent:<s>  - found unless the body contains <s>
  present:<s> - found only if the body contains <s>
  manual      - site blocks automated checks; we only provide the link
"""

import re
from concurrent.futures import ThreadPoolExecutor

import requests

from .. import net
from . import ModuleError, module

SITES = [
    # name, category, profile url, probe url (None = same), check
    ("GitHub", "dev", "https://github.com/{}", None, "status"),
    ("GitLab", "dev", "https://gitlab.com/{}", "https://gitlab.com/api/v4/users?username={}", "absent:[]"),
    ("Bitbucket", "dev", "https://bitbucket.org/{}/", None, "status"),
    ("Docker Hub", "dev", "https://hub.docker.com/u/{}", "https://hub.docker.com/v2/users/{}/", "status"),
    ("PyPI", "dev", "https://pypi.org/user/{}/", None, "status"),
    ("npm", "dev", "https://www.npmjs.com/~{}", None, "status"),
    ("Dev.to", "dev", "https://dev.to/{}", None, "status"),
    ("Hacker News", "dev", "https://news.ycombinator.com/user?id={}",
     "https://hacker-news.firebaseio.com/v0/user/{}.json", "absent:null"),
    ("Replit", "dev", "https://replit.com/@{}", None, "status"),
    ("CodePen", "dev", "https://codepen.io/{}", None, "status"),
    ("Codeforces", "dev", "https://codeforces.com/profile/{}",
     "https://codeforces.com/api/user.info?handles={}", "present:\"OK\""),
    ("Hugging Face", "dev", "https://huggingface.co/{}", None, "status"),
    ("Kaggle", "dev", "https://www.kaggle.com/{}", None, "status"),
    ("TryHackMe", "security", "https://tryhackme.com/p/{}",
     "https://tryhackme.com/api/user/exist/{}", "present:\"success\":true"),
    ("Keybase", "security", "https://keybase.io/{}",
     "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "absent:\"them\":[null]"),
    ("Reddit", "social", "https://www.reddit.com/user/{}", "https://www.reddit.com/user/{}/about.json", "status"),
    ("Mastodon (social)", "social", "https://mastodon.social/@{}",
     "https://mastodon.social/api/v1/accounts/lookup?acct={}", "status"),
    ("Bluesky", "social", "https://bsky.app/profile/{}.bsky.social",
     "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social", "status"),
    ("Telegram", "social", "https://t.me/{}", None, "present:tgme_page_title"),
    ("Wikipedia", "social", "https://en.wikipedia.org/wiki/User:{}",
     "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={}&format=json", "absent:\"missing\""),
    ("Linktree", "social", "https://linktr.ee/{}", None, "status"),
    ("About.me", "social", "https://about.me/{}", None, "status"),
    ("Gravatar", "social", "https://gravatar.com/{}", "https://en.gravatar.com/{}.json", "status"),
    ("YouTube", "video", "https://www.youtube.com/@{}", None, "status"),
    ("Vimeo", "video", "https://vimeo.com/{}", None, "status"),
    ("SoundCloud", "music", "https://soundcloud.com/{}", None, "status"),
    ("Last.fm", "music", "https://www.last.fm/user/{}", None, "status"),
    ("Behance", "creative", "https://www.behance.net/{}", None, "status"),
    ("Dribbble", "creative", "https://dribbble.com/{}", None, "status"),
    ("Flickr", "creative", "https://www.flickr.com/people/{}", None, "status"),
    ("Patreon", "creative", "https://www.patreon.com/{}", None, "status"),
    ("Ko-fi", "creative", "https://ko-fi.com/{}", None, "status"),
    ("Buy Me a Coffee", "creative", "https://www.buymeacoffee.com/{}", None, "status"),
    ("Chess.com", "gaming", "https://www.chess.com/member/{}", "https://api.chess.com/pub/player/{}", "status"),
    ("Lichess", "gaming", "https://lichess.org/@/{}", "https://lichess.org/api/user/{}", "status"),
    ("Steam", "gaming", "https://steamcommunity.com/id/{}", None,
     "absent:The specified profile could not be found"),
    ("Duolingo", "other", "https://www.duolingo.com/profile/{}",
     "https://www.duolingo.com/2017-06-30/users?username={}", "absent:\"users\":[]"),
    # Sites that block unauthenticated checks - link only.
    ("X / Twitter", "social", "https://x.com/{}", None, "manual"),
    ("Instagram", "social", "https://www.instagram.com/{}/", None, "manual"),
    ("Facebook", "social", "https://www.facebook.com/{}", None, "manual"),
    ("TikTok", "social", "https://www.tiktok.com/@{}", None, "manual"),
    ("Threads", "social", "https://www.threads.net/@{}", None, "manual"),
    ("LinkedIn", "social", "https://www.linkedin.com/in/{}", None, "manual"),
    ("Pinterest", "social", "https://www.pinterest.com/{}/", None, "manual"),
    ("Snapchat", "social", "https://www.snapchat.com/add/{}", None, "manual"),
    ("Twitch", "video", "https://www.twitch.tv/{}", None, "manual"),
    ("Medium", "social", "https://medium.com/@{}", None, "manual"),
]

VALID = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def check_site(site, username):
    name, category, profile, probe, check = site
    url = profile.format(username)
    result = {"site": name, "category": category, "url": url}
    if check == "manual":
        return {**result, "status": "manual"}
    probe_url = (probe or profile).format(username)
    try:
        resp = net.get(probe_url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return {**result, "status": "error", "detail": type(exc).__name__}
    return {**result, **interpret(check, resp.status_code, resp.text)}


def interpret(check, status_code, body):
    if status_code in (403, 429, 503):
        return {"status": "error", "detail": f"HTTP {status_code} (blocked/rate limited)"}
    if check == "status":
        if status_code == 200:
            return {"status": "found"}
        if status_code in (404, 410):
            return {"status": "not_found"}
        return {"status": "error", "detail": f"HTTP {status_code}"}
    mode, _, needle = check.partition(":")
    if status_code == 404:
        return {"status": "not_found"}
    body = body or ""
    if mode == "absent":
        compact = "".join(body.split())
        if needle in ("[]", "null"):  # whole-body sentinels; don't substring-match
            missing = compact == needle
        else:
            missing = needle in body or needle.replace(" ", "") in compact
        return {"status": "not_found" if missing else "found"}
    if mode == "present":
        return {"status": "found" if needle in body else "not_found"}
    return {"status": "error", "detail": "bad check"}


@module("username", "Username Search", ["username", "email"],
        f"Checks {len(SITES)} platforms for an account with this username.", order=10)
def username(target):
    handle = target.split("@", 1)[0] if "@" in target else target
    if not VALID.match(handle):
        raise ModuleError("Username contains characters no platform allows")
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda s: check_site(s, handle), SITES))
    order = {"found": 0, "manual": 1, "error": 2, "not_found": 3}
    results.sort(key=lambda r: (order[r["status"]], r["site"].lower()))
    counts = {k: sum(1 for r in results if r["status"] == k) for k in order}
    return {"username": handle, "checked": len(results), "counts": counts, "results": results}
