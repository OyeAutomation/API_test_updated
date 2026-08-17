from __future__ import annotations
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
from src.curl_parser import parse_curl, curl_to_requests_kwargs
from src.crypto_adapter import CryptoAdapter
from src.test_case_loader import load_test_cases
from src.mandatory_detector import detect_mandatory_fields
from src.request_builder import build_mutated_request, send_request

logger = logging.getLogger(__name__)


def run_suite(
    curl_command: str,
    crypto_profile_config: Optional[Dict] = None,
    test_case_file: Optional[str] = None,
    settings: Optional[Settings] = None,
    cancel_event: Optional[threading.Event] = None,
    response_crypto_config: Optional[Dict] = None,
) -> List[TestResult]:
    """Run the full test suite against the API defined by a curl command.

    Args:
        curl_command: Raw curl command string
        crypto_profile_config: Optional dict with crypto profile config
        test_case_file: Path to test cases xlsx file
        settings: Optional settings override
        response_crypto_config: Optional dict with separate response crypto profile

    Returns:
        List of TestResult objects
    """
    if settings is None:
        settings = Settings()

    # Parse curl
    parsed = parse_curl(curl_command)
    logger.info(f"Parsed: {parsed.method} {parsed.url}")

    # Setup crypto
    adapter = CryptoAdapter()
    if crypto_profile_config:
        from src.models import CryptoProfile
        profile = CryptoProfile(**crypto_profile_config)
        response_profile = None
        if response_crypto_config and response_crypto_config is not crypto_profile_config:
            response_profile = CryptoProfile(**response_crypto_config)
        adapter = CryptoAdapter(profile, response_profile)
        logger.info(f"Crypto: {profile.algorithm} with {profile.key_derivation}")
        if response_profile:
            logger.info(f"Response crypto: {response_profile.algorithm} with {response_profile.key_derivation}")

    # Load test cases
    test_cases = []
    if test_case_file:
        test_cases = load_test_cases(test_case_file, enabled_only=True)
    else:
        # Try default location
        default_path = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
        if default_path.exists():
            test_cases = load_test_cases(str(default_path), enabled_only=True)
        else:
            logger.warning("No test case file found, running with minimal cases")

    logger.info(f"Loaded {len(test_cases)} test cases")

    # Separate header/global vs payload-key scoped tests
    header_tests = [tc for tc in test_cases if tc.scope in (TestCaseScope.HEADER, TestCaseScope.GLOBAL)]
    payload_tests = [tc for tc in test_cases if tc.scope == TestCaseScope.PAYLOAD_KEY]

    results: List[TestResult] = []

    # 1. Run header-scope tests
    logger.info(f"Running {len(header_tests)} header/global test cases...")
    for tc in header_tests:
        if cancel_event and cancel_event.is_set():
            logger.info("Test run cancelled")
            break
        try:
            result = _run_single_test(parsed, tc, "", adapter, settings)
            results.append(result)
            time.sleep(settings.request_delay_ms / 1000.0)
        except Exception as e:
            logger.error(f"Header test {tc.test_case_id} failed: {e}")
            results.append(TestResult(
                api=parsed.url,
                key="",
                test_case=tc.description,
                test_case_type="Error",
                status=f"Error: {str(e)}",
                mandatory="N/A",
                status_code=0,
            ))

    # 2. Detect mandatory fields
    mandatory_results = detect_mandatory_fields(parsed, settings, adapter, cancel_event)
    logger.info(f"Mandatory detection: {len(mandatory_results)} keys checked")
    with open("/tmp/mandatory_debug.log", "a") as f:
        f.write(f"detect_mandatory_fields returned {len(mandatory_results)} keys: {list(mandatory_results.keys())[:10]}\n")
        for k, v in mandatory_results.items():
            f.write(f"  {k}: is_mandatory={v.is_mandatory}\n")
        f.write(f"body_json={parsed.body_json}, body_raw_len={len(parsed.body_raw) if parsed.body_raw else 0}\n")
        f.write(f"full_body_mode={parsed.body_json is None and adapter.profile is not None and bool(parsed.body_raw)}\n")
        f.write(f"checksum_mode={adapter.has_checksum_mode()}\n")

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

    with open("/tmp/mandatory_debug.log", "a") as f:
        f.write(f"After decision: mandatory_keys={len(mandatory_keys)}, testing_all_keys={testing_all_keys}\n")
        f.write(f"  payload_tests={len(payload_tests)}\n")
    logger.warning(f"mandatory_keys count={len(mandatory_keys)}, testing_all_keys={testing_all_keys}")
    logger.info(f"Running payload tests on {len(mandatory_keys)} keys, "
                f"{len(payload_tests)} test cases each...")

    for key_path in sorted(mandatory_keys):
        if cancel_event and cancel_event.is_set():
            logger.info("Payload tests cancelled")
            break
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
                result = _run_single_test(parsed, tc, key_path, adapter, settings)
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

    try:
        resp = send_request(kwargs, adapter, timeout=timeout_seconds)
    except requests.Timeout:
        return TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_type=tc.test_case_type.value,
            status="Request timed out",
            mandatory="N/A",
            status_code=0,
            response="",
        )
    except requests.ConnectionError as e:
        return TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_type=tc.test_case_type.value,
            status=f"Connection error: {str(e)[:100]}",
            mandatory="N/A",
            status_code=0,
            response="",
        )
    except Exception as e:
        return TestResult(
            api=parsed.url,
            key=key_path,
            test_case=tc.description,
            test_case_type=tc.test_case_type.value,
            status=f"Error: {str(e)[:200]}",
            mandatory="N/A",
            status_code=0,
            response="",
        )

    # Determine status message
    status_code = resp.status_code
    status_msg = _evaluate_status(tc, status_code, resp)
    decrypted_resp = getattr(resp, '_crypto_decrypted', None)
    resp_body = resp.text[:500]
    decrypted_resp_str = (decrypted_resp[:500] if isinstance(decrypted_resp, str) else "")
    encrypted_payload = getattr(resp, '_encrypted_payload', '')

    return TestResult(
        api=parsed.url,
        key=key_path,
        test_case=tc.description,
        test_case_type=tc.test_case_type.value,
        status=status_msg,
        mandatory="N/A",
        status_code=status_code,
        response=resp_body,
        decrypted_response=decrypted_resp_str,
        decrypted_payload=decrypted_payload,
        encrypted_payload=encrypted_payload,
    )


def _evaluate_status(tc: TestCase, status_code: int, resp: requests.Response) -> str:
    """Generate a human-readable status message based on test case and response."""
    mutation_type = tc.mutation_type
    behavior = tc.expected_behavior or ""

    # Check expected status code range
    range_str = tc.expected_status_code_range
    range_match = False
    if range_str and "-" in range_str:
        try:
            low, high = range_str.split("-")
            range_match = int(low) <= status_code <= int(high)
        except ValueError:
            range_match = False

    resp_text = getattr(resp, '_crypto_decrypted', None) or resp.text
    resp_text = resp_text[:200].replace("\n", " ")

    if mutation_type in (MutationType.AUTH_TOKEN_MISSING, MutationType.AUTH_TOKEN_INVALID,
                         MutationType.AUTH_TOKEN_EXPIRED, MutationType.HEADER_MISSING):
        if status_code == 401:
            return f"Rejected with 401 Unauthorized"
        elif range_match:
            return f"Rejected ({status_code}) — within expected range"
        else:
            return f"Unexpected status: {status_code} (wanted {range_str})"

    elif mutation_type in (MutationType.SQL_INJECTION, MutationType.XSS_PAYLOAD,
                           MutationType.SPECIAL_CHARS, MutationType.UNICODE_EMOJI):
        if range_match:
            return f"Rejected malicious payload ({status_code}) — " + behavior[:80]
        elif status_code < 400:
            return f"Accepted malicious payload ({status_code}) — VULNERABLE"
        else:
            return f"Rejected ({status_code}) but outside expected range {range_str}"

    elif mutation_type in (MutationType.MAX_LENGTH_EXCEED, MutationType.OVERSIZED_PAYLOAD):
        if range_match:
            return f"Rejected oversized input ({status_code})"
        elif status_code < 400:
            return f"Accepted oversized input ({status_code}) — possible issue"
        else:
            return f"Rejected ({status_code}) outside expected range"

    elif mutation_type == MutationType.REMOVE_KEY:
        if status_code >= 400:
            return f"Rejected missing key ({status_code}) — field is mandatory"
        else:
            return f"Accepted missing key ({status_code}) — field may be optional"

    elif mutation_type == MutationType.WRONG_TYPE:
        if range_match:
            return f"Rejected type mismatch ({status_code})"
        elif status_code < 400:
            return f"Accepted type mismatch ({status_code}) — weak typing"
        else:
            return f"Rejected ({status_code})"

    elif mutation_type == MutationType.NULL_VALUE:
        if status_code >= 400:
            return f"Rejected null value ({status_code})"
        else:
            return f"Accepted null value ({status_code})"

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
