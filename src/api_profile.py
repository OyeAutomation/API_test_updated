from __future__ import annotations
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, Field

from src.models import ParsedRequest, TestCase, TestCaseScope, MutationType

BODY_METHODS = ("POST", "PUT", "PATCH")


class ApiArchetype(str, Enum):
    READ_LIST = "read_list"
    WRITE = "write"
    LOGIN = "login"
    OTP = "otp"
    EXPORT = "export"
    JOB = "job"
    GENERIC = "generic"


class ApiProfile(BaseModel):
    """Declares how to test an endpoint — not what to expect.

    The test engine reads the profile to select applicable test cases and to
    evaluate responses against the standard HTTP contract:
    invalid payload -> 4xx, invalid/expired token -> 401, success -> 200.
    """

    name: str
    match: Optional[str] = None  # URL substring used to auto-match a curl to this profile
    archetype: ApiArchetype = ApiArchetype.GENERIC
    method: Optional[str] = None
    auth_required: bool = True
    body_type: str = "json"  # none | json | checksum
    query_params: List[str] = Field(default_factory=list)
    sensitive_fields: List[str] = Field(default_factory=list)
    expected_success_code: int = 200
    auth_rejection_codes: List[int] = Field(default_factory=lambda: [401])
    validation_rejection_codes: List[int] = Field(default_factory=lambda: [400, 422])
    response_schema: Optional[Dict] = None
    sla_seconds: Optional[float] = None
    idempotency_required: bool = False  # enables the duplicate-submit test
    idempotency_key: Optional[str] = None  # body field the server dedups on
    check_security_headers: bool = True  # CSP / HSTS / X-Content-Type-Options


def load_profiles(profile_dir: str | Path) -> Dict[str, ApiProfile]:
    """Load all *.yaml / *.yml profile files from a directory.

    Each file may hold either a single profile mapping or a list under a
    'profiles' key. Returns a dict keyed by profile name.
    """
    profiles: Dict[str, ApiProfile] = {}
    profile_dir = Path(profile_dir)
    if not profile_dir.exists():
        return profiles
    for f in sorted(list(profile_dir.glob("*.yaml")) + list(profile_dir.glob("*.yml"))):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as e:
            raise ValueError(f"Failed to load profile file {f}: {e}")
        items = data.get("profiles", [data]) if isinstance(data, dict) else []
        if isinstance(items, dict):
            items = [items]
        for item in items:
            if not isinstance(item, dict) or not item.get("name"):
                raise ValueError(f"Profile file {f} must contain 'name' for each profile")
            p = ApiProfile(**item)
            profiles[p.name] = p
    return profiles


def find_profile(
    profiles: Dict[str, ApiProfile],
    parsed: ParsedRequest,
    curl_name: Optional[str] = None,
) -> Optional[ApiProfile]:
    """Resolve the profile for a parsed request.

    Match order:
      1. Profile name == curl file stem (batch mode)
      2. Profile 'match' substring found in the request URL
    Returns None when no profile matches (generic behavior).
    """
    if not profiles:
        return None
    if curl_name:
        stem = Path(curl_name).stem.lower()
        for p in profiles.values():
            if p.name.lower() == stem:
                return p
    url_lower = parsed.url.lower()
    for p in profiles.values():
        if p.match and p.match.lower() in url_lower:
            return p
    return None


def _is_auth_test(tc: TestCase) -> bool:
    if tc.mutation_type in (
        MutationType.AUTH_TOKEN_MISSING,
        MutationType.AUTH_TOKEN_INVALID,
        MutationType.AUTH_TOKEN_EXPIRED,
    ):
        return True
    if tc.mutation_type == MutationType.HEADER_MISSING:
        return "content-type" not in (tc.mutation_value or "").lower()
    return False


def _is_content_type_test(tc: TestCase) -> bool:
    if tc.mutation_type == MutationType.HEADER_INVALID_VALUE:
        return "content-type" in (tc.mutation_value or "").lower()
    if tc.mutation_type == MutationType.HEADER_MISSING:
        return "content-type" in (tc.mutation_value or "").lower()
    return False


def test_applicable(
    tc: TestCase,
    parsed: ParsedRequest,
    profile: Optional[ApiProfile],
) -> Tuple[bool, str]:
    """Return (applicable, reason) for a test case against a parsed request.

    When profile is None, no tests are skipped (current behavior).
    """
    has_body = parsed.body_json is not None or bool(parsed.body_raw)

    if tc.scope == TestCaseScope.PAYLOAD_KEY:
        if not has_body:
            return False, "endpoint has no request body"
        return True, ""

    if tc.scope == TestCaseScope.GLOBAL:
        return _global_applicable(tc, parsed, profile, has_body)

    return _header_applicable(tc, parsed, profile, has_body)


def _global_applicable(
    tc: TestCase,
    parsed: ParsedRequest,
    profile: Optional[ApiProfile],
    has_body: bool,
) -> Tuple[bool, str]:
    mutation_type = tc.mutation_type

    if mutation_type == MutationType.MALFORMED_JSON:
        if not has_body:
            return False, "endpoint has no request body"
        return True, ""

    if mutation_type in (MutationType.INJECT_EXTRA_KEY, MutationType.ERROR_LEAK_SCAN,
                         MutationType.DUPLICATE_SUBMIT):
        if not has_body:
            return False, "endpoint has no request body"
        if mutation_type == MutationType.DUPLICATE_SUBMIT:
            # Skip only when a profile explicitly declares the endpoint is not
            # idempotent; without a profile the check still runs (universal).
            if profile is not None and not profile.idempotency_required:
                return False, "idempotency test not enabled in profile"
        return True, ""

    if mutation_type in (MutationType.QUERY_PARAM_INVALID, MutationType.QUERY_PARAM_INJECT):
        if not parsed.query_params and not (profile and profile.query_params):
            return False, "endpoint has no query parameters"
        return True, ""

    if mutation_type == MutationType.SCHEMA_VALIDATION:
        if profile is None or not profile.response_schema:
            return False, "no response schema declared in profile"
        return True, ""

    if mutation_type == MutationType.SECURITY_HEADERS_CHECK:
        if profile is not None and not profile.check_security_headers:
            return False, "security-header check disabled in profile"
        return True, ""

    if _is_auth_test(tc):
        if profile is not None and not profile.auth_required:
            return False, "auth not required for this endpoint"
        return True, ""

    return True, ""


def _header_applicable(
    tc: TestCase,
    parsed: ParsedRequest,
    profile: Optional[ApiProfile],
    has_body: bool,
) -> Tuple[bool, str]:
    if _is_auth_test(tc):
        if profile is not None and not profile.auth_required:
            return False, "auth not required for this endpoint"
        return True, ""

    if _is_content_type_test(tc):
        if parsed.method not in BODY_METHODS:
            return False, "endpoint has no body (Content-Type not applicable)"
        return True, ""

    return True, ""