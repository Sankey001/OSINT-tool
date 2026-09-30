"""Entry point.

    python -m osint_tool                  # start the web UI
    python -m osint_tool scan example.com # run a scan in the terminal
"""

import argparse
import json
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor

from .detect import TYPES, normalize
from .modules import modules_for, run_module


def serve(args):
    from .app import create_app

    url = f"http://{args.host}:{args.port}"
    print(f"\n  Recon OSINT is running at {url}\n  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    create_app().run(host=args.host, port=args.port, debug=False, threaded=True)


def scan(args):
    kind, target = normalize(args.target, args.type)
    mods = modules_for(kind)
    if args.only:
        wanted = set(args.only.split(","))
        mods = [m for m in mods if m.name in wanted]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda m: run_module(m.name, target), mods))
    report = {"target": target, "type": kind, "results": results}
    if args.json:
        json.dump(report, sys.stdout, indent=2, default=str)
        print()
        return
    print(f"\n  Target: {target}  ({kind})\n")
    for r in results:
        mark = "\033[32m✔\033[0m" if r["ok"] else "\033[31m✘\033[0m"
        print(f"  {mark} {r['title']}  ({r['elapsed_ms']} ms)")
        if not r["ok"]:
            print(f"      {r['error']}")
            continue
        body = json.dumps(r["data"], indent=2, default=str).splitlines()
        for line in body[:40]:
            print("      " + line)
        if len(body) > 40:
            print(f"      ... {len(body) - 40} more lines (use --json for everything)")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="osint_tool", description="Recon OSINT toolkit")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="start the web UI (default)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=5000)
    p_serve.add_argument("--no-browser", action="store_true")

    p_scan = sub.add_parser("scan", help="scan a target from the terminal")
    p_scan.add_argument("target")
    p_scan.add_argument("--type", choices=TYPES, help="override auto-detection")
    p_scan.add_argument("--only", help="comma-separated module names")
    p_scan.add_argument("--json", action="store_true", help="print the raw JSON report")

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        scan(args)
    else:
        if args.cmd is None:
            args = p_serve.parse_args([])
        serve(args)


if __name__ == "__main__":
    main()
