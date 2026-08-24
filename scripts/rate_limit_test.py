#!/usr/bin/env python3
"""Rate-limit / abuse-prevention test (opt-in, DESTRUCTIVE).

Sends the same request in a tight loop to check whether the API returns
429 Too Many Requests. This can trigger real account lockouts on production
systems — only run against test accounts/environments.

Usage:
    python scripts/rate_limit_test.py --curl-file request.curl --requests 100
"""
import argparse
import sys
import time
from pathlib import Path

import requests

from src.curl_parser import parse_curl, curl_to_requests_kwargs

WARN = (
    "\nWARNING: This is a destructive test. It hammers the target endpoint and "
    "can lock real accounts or trip WAF/rate-limiter bans. "
    "Run against TEST accounts only.\n"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curl-file", required=True, help="Path to .curl file")
    parser.add_argument("--requests", type=int, default=100, help="Number of requests (default 100)")
    parser.add_argument("--delay-ms", type=int, default=0, help="Delay between requests (default 0)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
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
    print(f"Sending {args.requests} requests...")

    status_counts = {}
    start = time.monotonic()
    for i in range(args.requests):
        try:
            resp = requests.request(method=method, url=url, timeout=args.timeout, **kwargs)
            status_counts[resp.status_code] = status_counts.get(resp.status_code, 0) + 1
        except requests.RequestException as e:
            status_counts["error"] = status_counts.get("error", 0) + 1
            print(f"  request {i + 1}: error {e}")
        if args.delay_ms:
            time.sleep(args.delay_ms / 1000.0)
    elapsed = time.monotonic() - start

    print(f"\nCompleted in {elapsed:.1f}s ({args.requests / elapsed:.0f} req/s)")
    print("Status code distribution:")
    for code, count in sorted(status_counts.items(), key=lambda kv: -kv[1]):
        print(f"  {code}: {count}")

    rate_limited = status_counts.get(429, 0)
    if rate_limited:
        print(f"\nPASS: rate limiting enforced ({rate_limited}/{args.requests} requests rejected with 429)")
        return 0
    print(f"\nFAIL: no 429 responses — rate limiting not detected on this endpoint")
    return 1


if __name__ == "__main__":
    sys.exit(main())
