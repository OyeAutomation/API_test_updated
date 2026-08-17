from __future__ import annotations
import json
import shlex
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Optional, List, Tuple
import base64

from src.models import ParsedRequest, HttpMethod

logger = logging.getLogger(__name__)


def parse_curl(curl_string: str) -> ParsedRequest:
    """Parse a curl command string into a ParsedRequest model.

    Uses shlex-based custom parser for maximum compatibility.
    """
    # Normalize line continuations and whitespace
    normalized = curl_string.replace("\\\n", " ").replace("\\\r\n", " ").strip()
    # Split into tokens using shlex
    try:
        tokens = shlex.split(normalized)
    except ValueError as e:
        raise ValueError(f"Failed to tokenize curl command: {e}")

    if not tokens:
        raise ValueError("Empty curl command")

    # Find the start of actual arguments (skip the 'curl' command itself)
    if tokens[0].lower() == "curl":
        tokens = tokens[1:]
    # Handle "postman request METHOD <url> ..." format (Postman exported style)
    elif len(tokens) >= 3 and tokens[0].lower() == "postman" and tokens[1].lower() == "request":
        method = tokens[2].upper()
        tokens = ["-X", method] + tokens[3:]

    return _parse_tokens(tokens)


def _parse_tokens(tokens: List[str]) -> ParsedRequest:
    method = HttpMethod.GET
    url = ""
    headers: List[Tuple[str, str]] = []
    query_params: Dict[str, List[str]] = {}
    body_parts: List[str] = []
    cookies: Dict[str, str] = {}
    user_credentials: Optional[str] = None
    i = 0

    while i < len(tokens):
        token = tokens[i]

        if token in ("-X", "--request"):
            i += 1
            if i < len(tokens):
                method = HttpMethod(tokens[i].upper())
        elif token in ("-H", "--header"):
            i += 1
            if i < len(tokens):
                header_line = tokens[i]
                if ":" in header_line:
                    key, value = header_line.split(":", 1)
                    headers.append((key.strip(), value.strip()))
        elif token in ("-d", "--data", "--data-raw", "--data-binary", "--body"):
            i += 1
            if i < len(tokens):
                body_parts.append(tokens[i])
        elif token == "--data-urlencode":
            i += 1
            if i < len(tokens):
                body_parts.append(tokens[i])
        elif token in ("-b", "--cookie"):
            i += 1
            if i < len(tokens):
                cookie_str = tokens[i]
                for part in cookie_str.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookies[k.strip()] = v.strip()
        elif token in ("-u", "--user"):
            i += 1
            if i < len(tokens):
                user_credentials = tokens[i]
        elif token in ("--compressed", "-k", "--insecure", "-s", "--silent"):
            if token in ("-k", "--insecure"):
                logger.info("Ignored --insecure/-k flag (TLS verification not handled by tool)")
            pass  # ignored silently
        elif token == "--url" and not url:
            i += 1
            if i < len(tokens):
                url = tokens[i]
                parsed_url = urlparse(url)
                if parsed_url.query:
                    qs = parse_qs(parsed_url.query, keep_blank_values=True)
                    query_params.update(qs)
                    url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        elif token.startswith("-"):
            # Unknown flag - skip it and its value if it expects one
            pass
        elif not url:
            url = token
            # Extract query params from URL
            parsed = urlparse(url)
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                query_params.update(qs)
                # Strip query from URL
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        i += 1

    # Build headers dict (last one wins for duplicate keys)
    headers_dict: Dict[str, str] = {}
    for k, v in headers:
        headers_dict[k] = v

    # Handle basic auth from -u flag
    if user_credentials:
        encoded = base64.b64encode(user_credentials.encode()).decode()
        headers_dict.setdefault("Authorization", f"Basic {encoded}")

    # Determine method from body presence if not explicitly set
    body_raw = "&".join(body_parts) if body_parts else ""
    body_json: Optional[Dict] = None
    if body_raw:
        if method == HttpMethod.GET and body_parts:
            method = HttpMethod.POST
        # Try to parse as JSON
        ct = headers_dict.get("Content-Type", "")
        if "application/json" in ct.lower():
            try:
                body_json = json.loads(body_raw)
            except json.JSONDecodeError:
                pass
        else:
            try:
                body_json = json.loads(body_raw)
                if "application/x-www-form-urlencoded" not in ct.lower():
                    headers_dict.setdefault("Content-Type", "application/json")
            except json.JSONDecodeError:
                pass

    parsed = ParsedRequest(
        method=method,
        url=url,
        headers=headers_dict,
        query_params={k: v[0] if v else "" for k, v in query_params.items()},
        body_raw=body_raw,
        body_json=body_json,
        cookies=cookies,
    )
    return parsed


def curl_to_requests_kwargs(parsed: ParsedRequest) -> dict:
    """Convert ParsedRequest to arguments for requests.request()."""
    kwargs: dict = {
        "method": parsed.method.value,
        "url": parsed.url,
        "headers": parsed.headers,
    }
    if parsed.query_params:
        kwargs["params"] = parsed.query_params
    if parsed.body_json is not None:
        kwargs["json"] = parsed.body_json
    elif parsed.body_raw:
        kwargs["data"] = parsed.body_raw
    if parsed.cookies:
        kwargs["cookies"] = parsed.cookies
    return kwargs
