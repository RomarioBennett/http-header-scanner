"""Command-line interface.

Exit codes (handy in CI):
    0  every URL met the minimum grade
    1  at least one URL graded below --min-grade
    2  at least one URL could not be scanned
"""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console

from . import __version__
from .models import GRADES
from .report import render
from .scanner import DEFAULT_USER_AGENT, ScanError, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="headerscan",
        description="Grade a website's HTTP security headers from A to F.",
    )
    p.add_argument(
        "urls", nargs="+", help="URL(s) to scan; https:// is assumed if omitted"
    )
    p.add_argument("--timeout", type=float, default=10.0, help="seconds (default: 10)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument(
        "--min-grade",
        choices=list(GRADES),
        default="C",
        help="exit 1 if any grade is worse than this (default: C)",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification (for self-signed test hosts)",
    )
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out, err = Console(), Console(stderr=True)

    payload: list[dict] = []
    had_error = below_min = False

    for url in args.urls:
        try:
            result = scan(
                url,
                timeout=args.timeout,
                verify=not args.insecure,
                user_agent=args.user_agent,
            )
        except ScanError as exc:
            had_error = True
            payload.append({"url": url, "error": str(exc)})
            if not args.json:
                err.print(f"Error scanning {url}: {exc}", markup=False, highlight=False)
            continue

        payload.append(result.to_dict())
        if GRADES.index(result.grade) > GRADES.index(args.min_grade):
            below_min = True
        if not args.json:
            render(result, out)

    if args.json:
        print(json.dumps(payload, indent=2))

    if had_error:
        return 2
    return 1 if below_min else 0


if __name__ == "__main__":
    sys.exit(main())
