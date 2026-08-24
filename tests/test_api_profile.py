"""Unit tests for per-endpoint API profiles and archetype-driven test selection."""
import json
from pathlib import Path

import pytest

from src.api_profile import (
    ApiProfile,
    load_profiles,
    find_profile,
    test_applicable as profile_applicable,
)
from src.models import (
    ParsedRequest,
    TestCase as ApiTestCase,
    TestCaseScope as Scope,
    TestCaseType as TCaseType,
    MutationType,
)

TEST_CASES_DIR = Path(__file__).parent.parent / "config" / "api_profiles"


def _tc(tc_id: str, scope, mutation_type, mutation_value=None) -> ApiTestCase:
    return ApiTestCase(
        test_case_id=tc_id,
        scope=scope,
        test_case_type=TCaseType.VALIDATION,
        description=tc_id,
        mutation_type=mutation_type,
        mutation_value=mutation_value,
        applies_to_mandatory_only=False,
    )


def _parsed(method: str = "POST", body: bool = True) -> ParsedRequest:
    return ParsedRequest(
        method=method,
        url="https://app.example.com/api/test",
        headers={"Content-Type": "application/json"} if body else {},
        body_json={"username": "x"} if body else None,
        body_raw="" if body else "",
    )


class TestLoadProfiles:
    def test_loads_profiles_from_dir(self):
        profiles = load_profiles(TEST_CASES_DIR)
        assert profiles
        assert "mock-register" in profiles
        assert "benepik-verify-otp-example" in profiles

    def test_missing_dir_returns_empty(self, tmp_path):
        assert load_profiles(tmp_path / "nope") == {}

    def test_invalid_file_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("name: [broken\n")
        with pytest.raises(ValueError):
            load_profiles(tmp_path)

    def test_profile_without_name_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("archetype: write\n")
        with pytest.raises(ValueError):
            load_profiles(tmp_path)


class TestFindProfile:
    def test_match_by_curl_stem(self):
        profiles = load_profiles(TEST_CASES_DIR)
        parsed = _parsed()
        found = find_profile(profiles, parsed, "mock-register.curl")
        assert found is not None
        assert found.name == "mock-register"

    def test_match_by_url_substring(self):
        profiles = load_profiles(TEST_CASES_DIR)
        parsed = _parsed(body=False)
        parsed.url = "https://app.benepik.in/verify-otp"
        found = find_profile(profiles, parsed, None)
        assert found is not None
        assert found.name == "benepik-verify-otp-example"

    def test_no_match_returns_none(self):
        parsed = _parsed()
        parsed.url = "https://other.example.com/nope"
        assert find_profile({"mock-register": ApiProfile(name="mock-register")}, parsed) is None

    def test_empty_profiles_returns_none(self):
        assert find_profile({}, _parsed()) is None


class TestTestApplicable:
    def test_auth_test_skipped_when_public_profile(self):
        profile = ApiProfile(name="p", auth_required=False)
        tc = _tc("HDR-001", Scope.HEADER, MutationType.HEADER_MISSING, "Authorization")
        applicable, reason = profile_applicable(tc, _parsed(), profile)
        assert not applicable
        assert "auth not required" in reason

    def test_auth_test_applicable_when_auth_required(self):
        profile = ApiProfile(name="p", auth_required=True)
        tc = _tc("HDR-001", Scope.HEADER, MutationType.HEADER_MISSING, "Authorization")
        assert profile_applicable(tc, _parsed(), profile)[0]

    def test_auth_test_applicable_without_profile(self):
        tc = _tc("HDR-001", Scope.HEADER, MutationType.HEADER_MISSING, "Authorization")
        assert profile_applicable(tc, _parsed(), None)[0]

    def test_content_type_test_skipped_for_get(self):
        tc = _tc("HDR-004", Scope.HEADER, MutationType.HEADER_MISSING, "Content-Type")
        applicable, reason = profile_applicable(tc, _parsed(method="GET"), None)
        assert not applicable
        assert "no body" in reason

    def test_content_type_test_applicable_for_post(self):
        tc = _tc("HDR-004", Scope.HEADER, MutationType.HEADER_MISSING, "Content-Type")
        assert profile_applicable(tc, _parsed(method="POST"), None)[0]

    def test_payload_test_skipped_when_no_body(self):
        tc = _tc("VAL-001", Scope.PAYLOAD_KEY, MutationType.REMOVE_KEY)
        applicable, reason = profile_applicable(tc, _parsed(body=False), None)
        assert not applicable
        assert "no request body" in reason

    def test_payload_test_applicable_with_body(self):
        tc = _tc("VAL-001", Scope.PAYLOAD_KEY, MutationType.REMOVE_KEY)
        assert profile_applicable(tc, _parsed(), None)[0]

    def test_malformed_json_skipped_when_no_body(self):
        tc = _tc("GLB-001", Scope.GLOBAL, MutationType.MALFORMED_JSON)
        assert not profile_applicable(tc, _parsed(body=False), None)[0]
        assert profile_applicable(tc, _parsed(), None)[0]