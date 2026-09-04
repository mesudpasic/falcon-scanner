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
from engine.target import Target

AUDIT_PATH = Path(__file__).resolve().parent / "data" / "audit.log.jsonl"


def parse_params(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--param must be key=value, got: {pair!r}")
        key, _, value = pair.partition("=")
        out[key] = value
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized SQL injection scanner (CLI).")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--param", action="append", default=[], help="key=value (repeatable)")
    parser.add_argument("--allow-host", action="append", default=[], help="allowlisted host glob (repeatable)")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--consent", action="store_true", help="confirm you are authorized to test this target")
    parser.add_argument("--rate", type=float, default=10.0, help="max requests/sec")
    args = parser.parse_args()

    scope = Scope(
        allowed_hosts=args.allow_host,
        allow_private=args.allow_private,
        consent=args.consent,
    )
    config = ScanConfig(scope=scope, rate_limit_per_sec=args.rate)
    target = Target(url=args.url, method=args.method, params=parse_params(args.param))
    scanner = Scanner(config, audit=AuditLog(AUDIT_PATH))

    found = 0

    async def on_event(event: dict) -> None:
        nonlocal found
        etype = event["type"]
        if etype == "progress":
            print(f"[{event['step']}/{event['total_steps']}] {event['detector']} -> {event['parameter']}")
        elif etype == "finding":
            found += 1
            print(f"\n  [!] {event['severity'].upper()} {event['technique']} in '{event['parameter']}'")
            print(f"      payload : {event['payload']}")
            print(f"      evidence: {event['evidence']}")
            print(f"      conf    : {event['confidence']}\n")
        elif etype == "error":
            print(f"[blocked] {event['message']}", file=sys.stderr)
        elif etype == "scan_finished":
            print(f"\nDone. {event['findings']} finding(s).")

    await scanner.run(target, on_event)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
