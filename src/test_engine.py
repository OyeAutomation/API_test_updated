from __future__ import annotations
import copy
import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from src.models import (
    ParsedRequest,
    TestCase,
    TestResult,
    Settings,
    TestCaseScope,
    MutationType,
    MandatoryResult,
)
from src.api_profile import ApiProfile, test_applicable
from src.curl_parser import parse_curl
from src.crypto_adapter import CryptoAdapter
from src.test_case_loader import load_test_cases
from src.mandatory_detector import detect_mandatory_fields
from src.request_builder import build_mutated_request, send_request
from src.pause_controller import PauseController

logger = logging.getLogger(__name__)

AUTH_MUTATION_TYPES = (
    MutationType.AUTH_TOKEN_MISSING,
    MutationType.AUTH_TOKEN_INVALID,
    MutationType.AUTH_TOKEN_EXPIRED,
)

VULNERABILITY_MUTATION_TYPES = (
    MutationType.SQL_INJECTION,
    MutationType.XSS_PAYLOAD,
    MutationType.SPECIAL_CHARS,
    MutationType.UNICODE_EMOJI,
    MutationType.NOSQL_INJECTION,
    MutationType.QUERY_PARAM_INJECT,
)

SECURITY_HEADER_NAMES = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
)

SENSITIVE_FIELD_PATTERNS = (
    "password", "passwd", "secret", "api_key", "apikey",
    "access_token", "refresh_token", "otp", "pin", "auth_token",
)

ERROR_LEAK_PATTERNS = (
    "traceback", "stack trace", ".py\"", "line ", "syntax error",
    "fatal error", "nullpointer", "sql syntax", "mysql", "oracle",
    "org.", "com.mysql", "warning:", "exception in thread", "at java.",
)

BUSINESS_ERROR_MARKERS = (
    "error", "unauthorized", "invalid", "required", "missing", "failed",
    "failure", "locked", "denied", "expired", "incorrect", "cannot",
    "not allowed", "invalid checksum", "unauthorised",
)


def run_suite(
    curl_command: str,
    crypto_profile_config: Optional[Dict] = None,
    test_case_file: Optional[str] = None,
    settings: Optional[Settings] = None,
    cancel_event: Optional[threading.Event] = None,
    response_crypto_config: Optional[Dict] = None,
    profile: Optional[ApiProfile] = None,
    on_rate_limit: Optional[Callable] = None,
    pause_controller: Optional[PauseController] = None,
) -> List[TestResult]:
    """Run the full test suite against the API defined by a curl command.

    Args:
        curl_command: Raw curl command string
        crypto_profile_config: Optional dict with crypto profile config
        test_case_file: Path to test cases xlsx file
        settings: Optional settings override
        cancel_event: Optional threading.Event for cancellation
        response_crypto_config: Optional dict with separate response crypto profile
        profile: Optional ApiProfile declaring endpoint characteristics;
                 enables archetype-driven test selection and contract evaluation
        on_rate_limit: Optional callback(response, consecutive_blocks)
                 -> ("resume", None|new_delay_ms) | ("cancel", None).
                 When set, the run pauses and asks on every 429/IP-block
                 response; when unset (tests/scripts/CI) it warns, honors
                 Retry-After, and continues without hanging.

    Returns:
        List of TestResult objects
    """
    if settings is None:
        settings = Settings()

    from src.rate_limit import RateLimitGuard
    rate_guard = RateLimitGuard(settings, cancel_event, on_rate_limit)

    # Parse curl
    parsed = parse_curl(curl_command)
    logger.info(f"Parsed: {parsed.method} {parsed.url}")

    # Setup crypto
    adapter = CryptoAdapter()
    if crypto_profile_config:
        from src.models import CryptoProfile
        # NOTE: keep this in its own variable — the `profile` parameter is the
        # per-endpoint ApiProfile used for archetype-driven test selection.
        crypto_profile = CryptoProfile(**crypto_profile_config)
        response_profile = None
        if response_crypto_config is not None:
            response_profile = CryptoProfile(**response_crypto_config)
        adapter = CryptoAdapter(crypto_profile, response_profile)
        logger.info(f"Crypto: {crypto_profile.algorithm} with {crypto_profile.key_derivation}")
        if response_profile:
            logger.info(f"Response crypto: {response_profile.algorithm} with {response_profile.key_derivation}")

    # When a pause controller is supplied it becomes the authoritative holder
    # for parsed/settings/adapter/profile so mid-run edits take effect.
    if pause_controller is not None:
        pause_controller.update(parsed=parsed, settings=settings, adapter=adapter, profile=profile)

    # Load test cases: the built-in universal suite ALWAYS runs for every API.
    # An explicit bank (or the default xlsx) is merged in, deduped by
    # test_case_id with the built-in entries winning, so the universal checks
    # are permanent — they can never be removed or disabled via the bank.
    from src.test_cases_builtin import BUILTIN_TEST_CASES
    test_cases: List[TestCase] = copy.deepcopy(BUILTIN_TEST_CASES)
    if test_case_file:
        bank_cases = load_test_cases(test_case_file, enabled_only=True)
    else:
        # Try default location
        default_path = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
        if default_path.exists():
            bank_cases = load_test_cases(str(default_path), enabled_only=True)
        else:
            bank_cases = []
            logger.warning("No test case bank found - running with the built-in universal suite only")

    builtin_ids = {tc.test_case_id for tc in test_cases}
    for tc in bank_cases:
        if tc.test_case_id not in builtin_ids:
            test_cases.append(tc)

    logger.info(f"Loaded {len(test_cases)} test cases")

    # Separate header/global vs payload-key scoped tests
    header_tests = [tc for tc in test_cases if tc.scope in (TestCaseScope.HEADER, TestCaseScope.GLOBAL)]
    payload_tests = [tc for tc in test_cases if tc.scope == TestCaseScope.PAYLOAD_KEY]

    results: List[TestResult] = []

    # 1. Run header-scope tests
    logger.info(f"Running {len(header_tests)} header/global test cases...")
    for tc in header_tests:
        if pause_controller is not None:
            pause_controller.wait_if_paused(cancel_event)
            if pause_controller.parsed is not None:
                parsed = pause_controller.parsed
            if pause_controller.settings is not None:
                settings = pause_controller.settings
            adapter = pause_controller.adapter
            profile = pause_controller.profile
            rate_guard.settings = settings
        if cancel_event and cancel_event.is_set():
            logger.info("Test run cancelled")
            break
        applicable, reason = test_applicable(tc, parsed, profile)
        if not applicable:
            logger.info(f"  {tc.test_case_id}: N/A — {reason}")
            results.append(TestResult(
                api=parsed.url,
                key="",
                test_case=tc.description,
                test_case_id=tc.test_case_id,
                test_case_type="Skipped",
                status=f"N/A — {reason}",
                mandatory="N/A",
                status_code=0,
            ))
            continue
        try:
            result = _run_single_test(parsed, tc, "", adapter, settings, profile=profile, rate_guard=rate_guard)
            results.append(result)
            time.sleep(settings.request_delay_ms / 1000.0)
        except Exception as e:
            logger.error(f"Header test {tc.test_case_id} failed: {e}")
            results.append(TestResult(
                api=parsed.url,
                key="",
                test_case=tc.description,
                test_case_id=tc.test_case_id,
                test_case_type="Error",
                status=f"Error: {str(e)}",
                mandatory="N/A",
                status_code=0,
            ))

    # 2. Detect mandatory fields
    mandatory_results = detect_mandatory_fields(parsed, settings, adapter, cancel_event,
                                                rate_guard=rate_guard,
                                                pause_controller=pause_controller)
    logger.info(f"Mandatory detection: {len(mandatory_results)} keys checked")

    # 3. Run payload tests - only on mandatory keys (or all keys if include_non_mandatory)
    mandatory_keys = {k for k, v in mandatory_results.items() if v.is_mandatory}
    testing_all_keys = settings.include_non_mandatory
    if not mandatory_keys and (parsed.body_json or mandatory_results) and not testing_all_keys:
        # If no keys detected as mandatory, test all keys
        mandatory_keys = set(mandatory_results.keys())
        testing_all_keys = True
        logger.info("No mandatory keys detected - testing all keys (body_json={}, results={})".format(
            parsed.body_json is not None, len(mandatory_results)))

    if testing_all_keys:
        mandatory_keys = set(mandatory_results.keys())

    logger.info(f"mandatory_keys count={len(mandatory_keys)}, testing_all_keys={testing_all_keys}")
    logger.info(f"Running payload tests on {len(mandatory_keys)} keys, "
                f"{len(payload_tests)} test cases each...")

    # The loop re-evaluates the target key set on every pass so live settings
    # edits (include_non_mandatory) and mid-run payload swaps take effect.
    processed_keys: set = set()
    while True:
        if pause_controller is not None:
            pause_controller.wait_if_paused(cancel_event)
            if pause_controller.parsed is not None:
                parsed = pause_controller.parsed
            if pause_controller.settings is not None:
                settings = pause_controller.settings
            adapter = pause_controller.adapter
            profile = pause_controller.profile
            rate_guard.settings = settings

        if cancel_event and cancel_event.is_set():
            logger.info("Payload tests cancelled")
            break

        testing_all_keys = settings.include_non_mandatory
        target_keys = {k for k, v in mandatory_results.items() if v.is_mandatory}
        if testing_all_keys:
            target_keys = set(mandatory_results.keys())
        elif not target_keys and mandatory_results:
            target_keys = set(mandatory_results.keys())

        pending = [k for k in sorted(target_keys) if k not in processed_keys]
        if not pending:
            break
        key_path = pending[0]
        processed_keys.add(key_path)

        mr = mandatory_results.get(key_path)
        if mr is None:
            mr = MandatoryResult(is_mandatory=False, evidence_status_code=0, evidence_response_snippet="")
        is_mandatory_str = "Yes" if mr.is_mandatory else "No"
        applicable_tests = [
            tc for tc in payload_tests
            if testing_all_keys or not tc.applies_to_mandatory_only or is_mandatory_str == "Yes"
        ]
        for tc in applicable_tests:
            if cancel_event and cancel_event.is_set():
                logger.info("Payload tests cancelled")
                break
            try:
                result = _run_single_test(parsed, tc, key_path, adapter, settings, profile=profile, rate_guard=rate_guard)
                # Override mandatory field
                result.mandatory = is_mandatory_str
                results.append(result)
                time.sleep(settings.request_delay_ms / 1000.0)
            except Exception as e:
                logger.error(f"Payload test {tc.test_case_id} on {key_path} failed: {e}")
                results.append(TestResult(
                    api=parsed.url,
                    key=key_path,
                    test_case=tc.description,
                    test_case_id=tc.test_case_id,
                    test_case_type="Error",
                    status=f"Error: {str(e)}",
                    mandatory=is_mandatory_str,
                    status_code=0,
                ))

    logger.info(f"Total results: {len(results)}")
    return results


def _run_single_test(
    parsed: ParsedRequest,
    tc: TestCase,
    key_path: str,
    adapter: CryptoAdapter,
    settings: Settings,
    profile: Optional[ApiProfile] = None,
    rate_guard=None,
) -> TestResult:
    """Run a single test case and produce a result."""
    kwargs = build_mutated_request(
        parsed,
        key_path,
        tc.mutation_type,
        tc.mutation_value,
        crypto_adapter=adapter,
    )

    # Capture decrypted payload from kwargs before sending
    decrypted_payload = kwargs.pop("_decrypted_payload", "")

    timeout_seconds = settings.timeout_seconds
    if adapter.profile is not None:
        timeout_seconds = max(timeout_seconds, 60)  # extra time for crypto

    if tc.mutation_type == MutationType.DUPLICATE_SUBMIT:
        result = _run_duplicate_submit(parsed, tc, key_path, kwargs, adapter, settings,
                                       timeout_seconds, profile=profile, rate_guard=rate_guard)
        _log_test_result(result)
        return result

    start_time = time.monotonic()
    try:
        resp = send_request(kwargs, adapter, timeout=timeout_seconds, rate_guard=rate_guard)
    except requests.Timeout:
        result = TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_id=tc.test_case_id,
            test_case_type=tc.test_case_type.value,
            status="Request timed out",
            mandatory="N/A",
            status_code=0,
            response="",
        )
        _log_test_result(result)
        return result
    except requests.ConnectionError as e:
        result = TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_id=tc.test_case_id,
            test_case_type=tc.test_case_type.value,
            status=f"Connection error: {str(e)[:100]}",
            mandatory="N/A",
            status_code=0,
            response="",
        )
        _log_test_result(result)
        return result
    except Exception as e:
        result = TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_id=tc.test_case_id,
            test_case_type=tc.test_case_type.value,
            status=f"Error: {str(e)[:200]}",
            mandatory="N/A",
            status_code=0,
            response="",
        )
        _log_test_result(result)
        return result
    elapsed_ms = (time.monotonic() - start_time) * 1000

    # Determine status message
    status_code = resp.status_code
    status_msg = _evaluate_status(tc, status_code, resp, profile=profile, elapsed_ms=elapsed_ms)
    decrypted_resp = getattr(resp, '_crypto_decrypted', None)
    resp_body = resp.text[:500]
    decrypted_resp_str = (decrypted_resp[:500] if isinstance(decrypted_resp, str) else "")
    encrypted_payload = getattr(resp, '_encrypted_payload', '')

    result = TestResult(
        api=parsed.url,
        key=key_path,
        test_case=tc.description,
        test_case_id=tc.test_case_id,
        test_case_type=tc.test_case_type.value,
        status=status_msg,
        mandatory="N/A",
        status_code=status_code,
        response=resp_body,
        decrypted_response=decrypted_resp_str,
        decrypted_payload=decrypted_payload,
        encrypted_payload=encrypted_payload,
    )
    _log_test_result(result)
    return result


def _log_test_result(result: TestResult) -> None:
    """Emit one INFO log line per test case so the console shows the run live."""
    key = result.key or "(global/header)"
    logger.info(
        f"[{result.test_case_id}] {result.test_case} | key={key} | "
        f"HTTP {result.status_code} | {result.status}"
    )


def _run_duplicate_submit(
    parsed: ParsedRequest,
    tc: TestCase,
    key_path: str,
    kwargs: dict,
    adapter: CryptoAdapter,
    settings: Settings,
    timeout_seconds: int,
    profile: Optional[ApiProfile] = None,
    rate_guard=None,
) -> TestResult:
    """Send the same payload twice and compare outcomes (idempotency check).

    A unique value is injected into the profile's idempotency key (or the
    first body key) so the first submission is accepted and the second is the
    genuine duplicate.
    """
    import uuid

    body = kwargs.get("json")
    if isinstance(body, dict) and body:
        key = profile.idempotency_key if profile and profile.idempotency_key else None
        if not key:
            key = next(iter(body))
        unique_body = dict(body)
        unique_body[key] = f"dup-{uuid.uuid4().hex[:12]}"
        kwargs["json"] = unique_body
        kwargs["_decrypted_payload"] = json.dumps(unique_body)

    kwargs.pop("_decrypted_payload", None)  # internal key, not a requests kwarg

    statuses: List[int] = []
    first = second = None
    try:
        first = send_request(dict(kwargs), adapter, timeout=timeout_seconds, rate_guard=rate_guard)
        statuses.append(first.status_code)
        if (rate_guard is not None and rate_guard.cancel_event is not None
                and rate_guard.cancel_event.is_set()):
            statuses.append(0)
            return TestResult(
                api=parsed.url,
                key=key_path,
                test_case=tc.description,
                test_case_id=tc.test_case_id,
                test_case_type=tc.test_case_type.value,
                status="Duplicate submit: cancelled after rate-limit pause",
                mandatory="N/A",
                status_code=first.status_code,
            )
        time.sleep(settings.request_delay_ms / 1000.0)
        second = send_request(dict(kwargs), adapter, timeout=timeout_seconds, rate_guard=rate_guard)
        statuses.append(second.status_code)
    except requests.Timeout:
        statuses.append(0)
    except Exception as e:
        return TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_id=tc.test_case_id,
            test_case_type=tc.test_case_type.value,
            status=f"Error: {str(e)[:200]}",
            mandatory="N/A",
            status_code=0,
        )

    second_business = _parse_business_status(getattr(second, "_crypto_decrypted", None) or second.text)
    second_rejected = second.status_code >= 400 or (
        second.status_code < 400 and second_business and second_business["kind"] == "error"
    )
    second_accepted = not second_rejected and second.status_code > 0

    if second.status_code == 0:
        msg = "Duplicate submit: second request failed/timed out"
    elif second_rejected:
        msg = (f"Duplicate submit: 1st={first.status_code}, 2nd={second.status_code} — "
               f"duplicate rejected (idempotency enforced)")
    elif second_accepted:
        msg = (f"Duplicate submit: 1st={first.status_code}, 2nd={second.status_code} — "
               f"duplicate accepted (no duplicate prevention detected)")
    else:
        msg = f"Duplicate submit: 1st={first.status_code}, 2nd={second.status_code}"

    return TestResult(
        api=parsed.url,
        key=key_path,
        test_case=tc.description,
        test_case_id=tc.test_case_id,
        test_case_type=tc.test_case_type.value,
        status=msg,
        mandatory="N/A",
        status_code=second.status_code,
        response=first.text[:300],
    )


def _parse_business_status(text: str) -> Optional[Dict[str, str]]:
    """Parse business-level status from a JSON response body.

    Returns {'kind': 'error'|'success', 'message': str} or None when the body
    is not JSON or carries no business-status signal.

    Handles Benepik-style responses where HTTP is always 200 and the real
    outcome lives in fields like status (0/200) or success (0/1).
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    message = ""
    for key in ("message", "msg", "error_description"):
        val = data.get(key)
        if isinstance(val, str):
            message = val
            break

    success = data.get("success")
    status = data.get("status")

    verdict = None
    if success is not None:
        if isinstance(success, bool):
            verdict = "success" if success else "error"
        elif isinstance(success, (int, float)):
            verdict = "success" if success in (1, 200) else "error"
        elif isinstance(success, str):
            s = success.strip().lower()
            verdict = "success" if s in ("1", "true", "yes", "200", "ok") else "error"
    elif status is not None:
        if isinstance(status, bool):
            verdict = "success" if status else "error"
        elif isinstance(status, (int, float)):
            verdict = "success" if status in (1, 200) else "error"
        elif isinstance(status, str):
            s = status.strip().lower()
            if s in ("1", "true", "yes", "200", "ok", "success"):
                verdict = "success"
            elif s in ("0", "false", "no", "error", "failed"):
                verdict = "error"
    elif message:
        low = message.lower()
        if any(m in low for m in BUSINESS_ERROR_MARKERS):
            verdict = "error"
        else:
            verdict = "success"

    return {"kind": verdict, "message": message} if verdict else None


def _is_auth_test(tc: TestCase) -> bool:
    if tc.mutation_type in AUTH_MUTATION_TYPES:
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


def _evaluate_status(
    tc: TestCase,
    status_code: int,
    resp: requests.Response,
    profile: Optional[ApiProfile] = None,
    elapsed_ms: float = 0,
) -> str:
    """Generate a status message based on the standard HTTP contract and the
    response.

    Contract (per spec):
      - invalid/missing payload  -> 400 (any 4xx accepted)
      - invalid/expired token    -> 401 (custom codes via profile)
      - valid request            -> 200 (success)

    When the API hides a rejection behind HTTP 2xx with a business-level
    error in the body (status:0 / success:0 / error message), the result is
    flagged DEFECT — the API violates the contract.
    """
    mutation_type = tc.mutation_type
    behavior = tc.expected_behavior or ""

    resp_text = getattr(resp, "_crypto_decrypted", None) or resp.text
    resp_text = str(resp_text)
    snippet = resp_text[:200].replace("\n", " ")
    business = _parse_business_status(resp_text)

    # Check expected status code range
    range_str = tc.expected_status_code_range
    range_match = False
    if range_str and "-" in range_str:
        try:
            low, high = range_str.split("-")
            range_match = int(low) <= status_code <= int(high)
        except ValueError:
            range_match = False

    is_auth = _is_auth_test(tc)
    is_ct = _is_content_type_test(tc)

    # --- Response-level checks evaluated first (they inspect headers/body) ---
    if mutation_type == MutationType.SECURITY_HEADERS_CHECK:
        return _eval_security_headers(resp)
    if mutation_type == MutationType.CORS_CHECK:
        return _eval_cors(resp)
    if mutation_type == MutationType.SENSITIVE_DATA_SCAN:
        return _eval_sensitive_data(resp_text, profile)
    if mutation_type == MutationType.ERROR_LEAK_SCAN:
        return _eval_error_leak(status_code, resp_text)
    if mutation_type == MutationType.SCHEMA_VALIDATION:
        return _eval_schema(resp_text, profile)
    if mutation_type == MutationType.PERFORMANCE_CHECK:
        sla = profile.sla_seconds if profile and profile.sla_seconds else 2.0
        if elapsed_ms > sla * 1000:
            return f"SLA exceeded: {elapsed_ms:.0f} ms (limit {sla:g}s)"
        return f"SLA met: {elapsed_ms:.0f} ms (limit {sla:g}s)"

    # --- Baseline: valid request must return the expected success code ---
    if mutation_type == MutationType.BASELINE:
        expected = (profile.expected_success_code if profile else None) or 200
        if status_code == expected:
            return f"Baseline passed ({status_code}) — expected success code"
        if status_code < 400:
            return f"Baseline accepted with {status_code} (expected {expected})"
        return f"Baseline FAILED: got {status_code}, expected {expected}"

    # --- Business-level rejection hidden behind a 2xx status (contract violation) ---
    if status_code < 400 and business and business["kind"] == "error":
        msg = business["message"] or "business status indicates failure"
        if is_auth:
            return f"DEFECT: auth rejected via business status (HTTP {status_code}, '{msg}') — contract expects 401"
        if is_ct:
            return f"DEFECT: media-type rejection surfaced as HTTP {status_code} ('{msg}') — contract expects 400/415"
        if mutation_type == MutationType.MALFORMED_JSON:
            return f"DEFECT: malformed JSON rejected via business status (HTTP {status_code}, '{msg}') — contract expects 400"
        if mutation_type in VULNERABILITY_MUTATION_TYPES:
            return f"DEFECT: malicious payload rejected at business level (HTTP {status_code}, '{msg}') — contract expects 4xx"
        return f"DEFECT: rejection surfaced as HTTP {status_code} ('{msg}') — contract expects 4xx"

    # --- Auth contract ---
    if is_auth:
        allowed = (profile.auth_rejection_codes if profile else None) or [401]
        if status_code in allowed:
            return f"Rejected with {status_code} — auth enforced"
        if status_code >= 400:
            return f"Rejected ({status_code}) — outside expected auth codes {allowed}"
        return f"Accepted ({status_code}) — auth not enforced or token not validated"

    # --- Content-Type / media type contract ---
    if is_ct:
        if range_match:
            return f"Rejected ({status_code}) — within expected range"
        if status_code < 400:
            return f"Accepted ({status_code}) — Content-Type not enforced"
        return f"Rejected ({status_code}) — unexpected status"

    # --- Query-param validation (pagination / filter) ---
    if mutation_type == MutationType.QUERY_PARAM_INVALID:
        if range_match:
            return f"Rejected invalid query param ({status_code})"
        if status_code < 400:
            return f"Accepted invalid query param ({status_code}) — weak validation"
        return f"Rejected ({status_code}) — outside expected range"

    # --- Method not allowed ---
    if mutation_type == MutationType.METHOD_CHANGE:
        if status_code == 405:
            return f"Rejected with 405 Method Not Allowed"
        if 400 <= status_code < 500:
            return f"Rejected ({status_code}) — method not allowed (405 expected)"
        if status_code < 400:
            return f"Accepted ({status_code}) — unsupported method not restricted"
        return f"Rejected ({status_code}) — server error"

    # --- Mass assignment: extra key injection ---
    if mutation_type == MutationType.INJECT_EXTRA_KEY:
        if status_code < 400:
            return f"Accepted ({status_code}) — extra key accepted; verify server ignored it (manual review)"
        return f"Rejected ({status_code}) — unknown fields rejected"

    # --- Vulnerability payloads ---
    if mutation_type in VULNERABILITY_MUTATION_TYPES:
        if range_match:
            return f"Rejected malicious payload ({status_code}) — " + behavior[:80]
        elif status_code < 400:
            return f"Accepted malicious payload ({status_code}) — VULNERABLE"
        else:
            return f"Rejected ({status_code}) but outside expected range {range_str}"

    # --- Boundary: oversized inputs ---
    elif mutation_type in (MutationType.MAX_LENGTH_EXCEED, MutationType.OVERSIZED_PAYLOAD):
        if range_match:
            return f"Rejected oversized input ({status_code})"
        elif status_code < 400:
            return f"Accepted oversized input ({status_code}) — possible issue"
        else:
            return f"Rejected ({status_code}) outside expected range"

    # --- Mandatory field removal ---
    elif mutation_type == MutationType.REMOVE_KEY:
        if status_code >= 400:
            return f"Rejected missing key ({status_code}) — field is mandatory"
        else:
            return f"Accepted missing key ({status_code}) — field may be optional"

    # --- Type mismatch ---
    elif mutation_type == MutationType.WRONG_TYPE:
        if range_match:
            return f"Rejected type mismatch ({status_code})"
        elif status_code < 400:
            return f"Accepted type mismatch ({status_code}) — weak typing"
        else:
            return f"Rejected ({status_code})"

    # --- Null value ---
    elif mutation_type == MutationType.NULL_VALUE:
        if status_code >= 400:
            return f"Rejected null value ({status_code})"
        else:
            return f"Accepted null value ({status_code})"

    # --- Empty / zero-length value ---
    elif mutation_type in (MutationType.EMPTY_VALUE, MutationType.MIN_LENGTH_VIOLATE):
        if status_code >= 400:
            return f"Rejected empty/zero-length value ({status_code})"
        else:
            return f"Accepted empty value ({status_code})"

    else:
        if range_match:
            return f"Rejected ({status_code})"
        elif status_code < 400:
            return f"Accepted ({status_code})"
        else:
            return f"Rejected ({status_code}) — unexpected status"


def _eval_security_headers(resp: requests.Response) -> str:
    headers = {k.lower(): v for k, v in (getattr(resp, "headers", None) or {}).items()}
    missing = [h for h in SECURITY_HEADER_NAMES if h.lower() not in headers]
    if not missing:
        return "Security headers present: CSP, HSTS, X-Content-Type-Options"
    return f"Security headers missing: {', '.join(missing)}"


def _eval_cors(resp: requests.Response) -> str:
    headers = {k.lower(): v for k, v in (getattr(resp, "headers", None) or {}).items()}
    acao = headers.get("access-control-allow-origin")
    if not acao:
        return "Rejected (no Access-Control-Allow-Origin) — CORS not enabled"
    if "*" in acao or "evil" in acao.lower() or "null" in acao.lower():
        return f"VULNERABLE: Access-Control-Allow-Origin reflects '{acao}'"
    return f"CORS safe: Access-Control-Allow-Origin '{acao}' does not reflect the malicious origin"


def _eval_sensitive_data(resp_text: str, profile: Optional[ApiProfile]) -> str:
    fields = [f.lower() for f in (profile.sensitive_fields if profile else [])]
    if not fields:
        fields = list(SENSITIVE_FIELD_PATTERNS)
    lower = resp_text.lower()
    leaked = []
    for f in fields:
        # match JSON keys like "password": or "access_token":
        if f'"{(f or "")}":' in lower or f'"{f}"' in lower:
            leaked.append(f)
    if "bearer eyj" in lower:
        leaked.append("bearer token")
    if leaked:
        return f"VULNERABLE: sensitive data exposed in response ({', '.join(sorted(set(leaked)))})"
    return "No sensitive data detected in response"


def _eval_error_leak(status_code: int, resp_text: str) -> str:
    lower = resp_text.lower()
    for pattern in ERROR_LEAK_PATTERNS:
        if pattern.lower() in lower:
            return f"VULNERABLE: error response leaks internals (pattern: '{pattern}')"
    if status_code >= 400:
        return f"Rejected ({status_code}) with generic error — no information leakage"
    return f"Accepted ({status_code}) — error path did not trigger"


def _eval_schema(resp_text: str, profile: Optional[ApiProfile]) -> str:
    schema = profile.response_schema if profile else None
    if not schema:
        return "N/A — no response schema declared in profile"
    try:
        data = json.loads(resp_text)
    except (ValueError, TypeError):
        return f"Defect: response is not valid JSON — schema cannot be validated"
    if not isinstance(data, dict):
        return "Defect: response is not a JSON object — schema cannot be validated"

    issues = []
    for field, expected_type in schema.items():
        if field not in data:
            issues.append(f"missing '{field}'")
            continue
        actual = data[field]
        type_ok = _schema_type_matches(expected_type, actual)
        if not type_ok:
            issues.append(f"'{field}' expected {expected_type}, got {type(actual).__name__}")
    if issues:
        return "Schema mismatch: " + "; ".join(issues)
    return "Schema validated — response matches declared structure"


def _schema_type_matches(expected_type: str, value) -> bool:
    expected = str(expected_type).lower()
    if expected in ("int", "integer", "number", "numeric", "long", "float", "double"):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected in ("str", "string", "text", "varchar", "char"):
        return isinstance(value, str)
    if expected in ("bool", "boolean"):
        return isinstance(value, bool)
    if expected in ("list", "array"):
        return isinstance(value, list)
    if expected in ("dict", "object", "json"):
        return isinstance(value, dict)
    return True  # unknown type declaration -> do not fail
