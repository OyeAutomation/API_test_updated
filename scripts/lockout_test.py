#!/usr/bin/env python3
"""Account lockout / brute-force protection test (opt-in, DESTRUCTIVE).

Repeatedly submits an invalid credential (e.g. wrong OTP or password) to
check whether the API blocks the account after N attempts.

WARNING: this WILL lock the targeted account on real systems. Run against
dedicated test accounts only.

Usage:
    python scripts/lockout_test.py --curl-file login.curl --attempts 100
"""
import argparse
import sys
import time
from pathlib import Path

import requests

from src.curl_parser import parse_curl, curl_to_requests_kwargs

WARN = (
    "\nWARNING: This is a destructive test. It submits invalid credentials "
    "repeatedly and WILL lock the targeted account on real systems. "
    "Run against dedicated TEST accounts only.\n"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curl-file", required=True, help="Path to .curl file")
    parser.add_argument("--attempts", type=int, default=100, help="Number of attempts (default 100)")
    parser.add_argument("--delay-ms", type=int, default=200, help="Delay between attempts (default 200)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--lockout-keyword", default="lock",
                        help="Keyword in the response body that indicates lockout (default: 'lock')")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    args = parser.parse_args()

    if not args.yes:
        print(WARN)
        reply = input("Type 'run' to continue: ").strip().lower()
        if reply != "run":
            print("Aborted.")
            return 1

    curl_cmd = Path(args.curl_file).read_text(encoding="utf-8").strip()
    parsed = parse_curl(curl_cmd)
    kwargs = curl_to_requests_kwargs(parsed)
    method = kwargs.pop("method")
    url = kwargs.pop("url")

    print(f"Target: {method} {url}")
    print(f"Sending {args.attempts} invalid attempts...")

    locked = False
    lock_attempt = 0
    for i in range(1, args.attempts + 1):
        try:
            resp = requests.request(method=method, url=url, timeout=args.timeout, **kwargs)
            body = resp.text.lower()
            if args.lockout_keyword.lower() in body:
                locked = True
                lock_attempt = i
                print(f"  attempt {i}: LOCKED ({resp.status_code}) — {resp.text[:100]}")
                break
        except requests.RequestException as e:
            print(f"  attempt {i}: error {e}")
        if args.delay_ms:
            time.sleep(args.delay_ms / 1000.0)

    if locked:
        print(f"\nPASS: account locked after {lock_attempt} attempts")
        return 0
    print(f"\nFAIL: no lockout detected after {args.attempts} attempts")
    return 1


if __name__ == "__main__":
    sys.exit(main())
