"""Command-line frontend for the scan engine.

Mirrors the web API but runs a scan synchronously and prints events. Proves the
engine is UI-independent: CLI and GUI share the exact same core.

Example:
  python cli.py --url "http://testphp.vulnweb.com/listproducts.php" \
      --param cat=1 --allow-host testphp.vulnweb.com --consent
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from engine import AuditLog, ScanConfig, Scanner, Scope
from engine.crawler import target_from_url
from engine.tamper import available_tampers

AUDIT_PATH = Path(__file__).resolve().parent / "data" / "audit.log.jsonl"


def parse_pairs(pairs: list[str], flag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"{flag} must be key=value, got: {pair!r}")
        key, _, value = pair.partition("=")
        out[key] = value
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized SQL injection scanner (CLI).")
    parser.add_argument(
        "--url",
        action="append",
        default=[],
        help="Target URL (repeatable; scanned in parallel)",
    )
    parser.add_argument("--method", default="GET")
    parser.add_argument("--param", action="append", default=[], help="key=value (repeatable)")
    parser.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="name=value session cookie (repeatable)",
    )
    parser.add_argument("--allow-host", action="append", default=[], help="allowlisted host glob (repeatable)")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--consent", action="store_true", help="confirm you are authorized to test this target")
    parser.add_argument("--rate", type=float, default=10.0, help="max requests/sec")
    parser.add_argument("--concurrency", type=int, default=3, help="parallel URL / endpoint workers")
    parser.add_argument("--crawl", action="store_true", help="crawl starting URLs for more parameters")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--crawl-max-pages", type=int, default=50)
    parser.add_argument("--no-waf", action="store_true", help="skip WAF fingerprinting")
    parser.add_argument(
        "--tamper",
        action="append",
        default=[],
        help=f"evasion script (repeatable). Available: {', '.join(available_tampers())}",
    )
    parser.add_argument("--oob-callback", default="", help="base URL the DB can reach, e.g. http://IP:8000")
    parser.add_argument("--oob-domain", default="", help="DNS collaborator domain")
    parser.add_argument(
        "--oob-interactsh",
        default="",
        help="Interactsh server (e.g. oast.pro) — register, poll, and confirm DNS OOB",
    )
    parser.add_argument("--oob-interactsh-token", default="", help="Interactsh Authorization token")
    parser.add_argument(
        "--oob-poll-url",
        default="",
        help="Burp Collaborator / custom poll URL (token must appear in the response)",
    )
    parser.add_argument("--oob-poll-auth", default="", help="Authorization for --oob-poll-url")
    parser.add_argument(
        "--no-blind-enum",
        action="store_true",
        help="skip database/schema/table enumeration on the boolean-blind channel",
    )
    args = parser.parse_args()

    if not args.url:
        parser.error("at least one --url is required")

    scope = Scope(
        allowed_hosts=args.allow_host,
        allow_private=args.allow_private,
        consent=args.consent,
    )
    config = ScanConfig(
        scope=scope,
        rate_limit_per_sec=args.rate,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth,
        crawl_max_pages=args.crawl_max_pages,
        detect_waf=not args.no_waf,
        tampers=list(args.tamper),
        concurrency=max(1, args.concurrency),
        oob_callback=args.oob_callback,
        oob_domain=args.oob_domain,
        oob_interactsh=args.oob_interactsh,
        oob_interactsh_token=args.oob_interactsh_token,
        oob_poll_url=args.oob_poll_url,
        oob_poll_auth=args.oob_poll_auth,
        blind_enumerate=not args.no_blind_enum,
    )
    params = parse_pairs(args.param, "--param")
    cookies = parse_pairs(args.cookie, "--cookie")
    targets = [
        target_from_url(url, method=args.method, extra_params=params, cookies=cookies)
        for url in args.url
    ]
    scanner = Scanner(config, audit=AuditLog(AUDIT_PATH))

    found = 0

    async def on_event(event: dict) -> None:
        nonlocal found
        etype = event["type"]
        url = event.get("url", "")
        prefix = f"[{url}] " if url else ""
        if etype == "progress":
            print(
                f"{prefix}[{event['step']}/{event['total_steps']}] "
                f"{event['detector']} -> {event['parameter']}"
            )
        elif etype == "finding":
            found += 1
            print(f"\n  [!] {event['severity'].upper()} {event['technique']} in '{event['parameter']}'")
            print(f"      payload : {event['payload']}")
            print(f"      evidence: {event['evidence']}")
            print(f"      conf    : {event['confidence']}\n")
        elif etype == "waf":
            if event.get("detected"):
                print(f"{prefix}[waf] {event.get('product')}: {event.get('evidence')}")
        elif etype == "crawled":
            print(f"[crawl] {event.get('endpoints')} endpoint(s) ({event.get('added')} new)")
        elif etype == "error":
            print(f"[blocked] {event['message']}", file=sys.stderr)
        elif etype == "scan_finished":
            print(f"\nDone. {event['findings']} finding(s).")

    await scanner.run(targets, on_event)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
