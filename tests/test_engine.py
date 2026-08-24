"""End-to-end tests for the orchestrator, running against the mock server
through Flask's test client (requests is monkeypatched to avoid sockets)."""
import json
import logging
import threading
import time as time_mod
from pathlib import Path

import pytest

from src.api_profile import ApiProfile
from src.models import Settings
from src.test_engine import run_suite


class FakeResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._encrypted_payload = ""

    def json(self):
        return json.loads(self.text)


@pytest.fixture
def engine_env(monkeypatch):
    from mock_server.app import app
    app.config["TESTING"] = True
    client = app.test_client()

    def fake_request(method, url, timeout=None, **kwargs):
        headers = kwargs.get("headers") or {}
        resp = client.open(
            url,
            method=method,
            headers=headers,
            query_string=kwargs.get("params"),
            json=kwargs.get("json"),
            data=kwargs.get("data"),
        )
        return FakeResponse(resp.status_code, resp.get_data(as_text=True), dict(resp.headers))

    import requests
    monkeypatch.setattr(requests, "request", fake_request)
    return client


REGISTER_CURL = (
    'curl -X POST http://localhost:5000/api/register '
    '-H "Content-Type: application/json" '
    '-H "Authorization: Bearer valid-token-12345" '
    '-d \'{"username":"john_doe","email":"john@test.com","password":"secret123"}\''
)


def _settings():
    return Settings(request_delay_ms=0, timeout_seconds=5, max_retries=1)


def test_run_suite_populates_test_case_id(engine_env):
    results = run_suite(REGISTER_CURL, settings=_settings())
    assert results
    by_id = {r.test_case_id: r for r in results}
    assert "GLB-001" in by_id
    assert "HDR-001" in by_id
    assert "VAL-001" in by_id
    for r in results:
        assert r.test_case_id, "test_case_id must not be empty"


def test_run_suite_glb001_malformed_json_rejected(engine_env):
    results = run_suite(REGISTER_CURL, settings=_settings())
    glb1 = next(r for r in results if r.test_case_id == "GLB-001")
    assert "Rejected" in glb1.status
    assert 400 <= glb1.status_code <= 499


def test_run_suite_header_auth_tests(engine_env):
    results = run_suite(REGISTER_CURL, settings=_settings())
    hdr2 = next(r for r in results if r.test_case_id == "HDR-002")
    # register endpoint has no auth requirement, so an invalid token is
    # accepted — this is expected framework behavior, not a crash
    assert hdr2.status_code in (200, 201, 401)


def test_run_suite_mandatory_detection_marks_keys(engine_env):
    results = run_suite(REGISTER_CURL, settings=_settings())
    payload = [r for r in results if r.key and r.mandatory == "Yes"]
    assert payload
    keys = {r.key for r in payload}
    assert {"username", "email", "password"} <= keys


def test_run_suite_no_debug_log_side_effect(engine_env):
    debug_log = Path("/tmp/mandatory_debug.log")
    before = debug_log.stat().st_mtime if debug_log.exists() else None
    run_suite(REGISTER_CURL, settings=_settings())
    if before is None:
        assert not debug_log.exists(), "debug log must not be created"
    else:
        assert debug_log.stat().st_mtime == before, "debug log must not be written"


def test_run_suite_connection_error_returns_result(engine_env, monkeypatch):
    import requests

    def boom(method, url, timeout=None, **kwargs):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "request", boom)
    results = run_suite(REGISTER_CURL, settings=_settings())
    assert results
    assert any("Connection error" in r.status or "Error" in r.status for r in results)


class FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
        self._crypto_decrypted = None

    def json(self):
        return json.loads(self.text)


class TestBusinessStatusDefectDetection:
    """HTTP 2xx + business-level error in body must be flagged DEFECT."""

    def _tc(self):
        from src.models import TestCase, TestCaseScope, TestCaseType, MutationType
        return TestCase(
            test_case_id="GLB-001",
            scope=TestCaseScope.GLOBAL,
            test_case_type=TestCaseType.VALIDATION,
            description="Malformed JSON body",
            mutation_type=MutationType.MALFORMED_JSON,
            expected_status_code_range="400-499",
            applies_to_mandatory_only=False,
            enabled=True,
        )

    def test_malformed_json_200_with_status0_is_defect(self):
        from src.test_engine import _evaluate_status
        tc = self._tc()
        resp = FakeResp(200, '{"status": 0, "message": "Invalid checksum"}')
        status = _evaluate_status(tc, 200, resp)
        assert status.startswith("DEFECT")
        assert "Invalid checksum" in status

    def test_success_200_is_not_defect(self):
        from src.test_engine import _evaluate_status
        tc = self._tc()
        resp = FakeResp(200, '{"success": 1, "message": "Data Fetch Successfully."}')
        status = _evaluate_status(tc, 200, resp)
        assert "DEFECT" not in status
        assert "Accepted" in status

    def test_auth_rejection_hidden_in_200_is_defect(self):
        from src.models import TestCase, TestCaseScope, TestCaseType, MutationType
        from src.test_engine import _evaluate_status
        tc = TestCase(
            test_case_id="HDR-002",
            scope=TestCaseScope.HEADER,
            test_case_type=TestCaseType.AUTH,
            description="Invalid token",
            mutation_type=MutationType.AUTH_TOKEN_INVALID,
            expected_status_code_range="401-401",
            applies_to_mandatory_only=False,
            enabled=True,
        )
        resp = FakeResp(200, '{"success": 0, "message": "Unauthorized"}')
        status = _evaluate_status(tc, 200, resp)
        assert status.startswith("DEFECT")
        assert "401" in status

    def test_auth_403_mapped_via_profile_is_rejection(self):
        from src.models import TestCase, TestCaseScope, TestCaseType, MutationType
        from src.test_engine import _evaluate_status
        tc = TestCase(
            test_case_id="HDR-002",
            scope=TestCaseScope.HEADER,
            test_case_type=TestCaseType.AUTH,
            description="Invalid token",
            mutation_type=MutationType.AUTH_TOKEN_INVALID,
            expected_status_code_range="401-401",
            applies_to_mandatory_only=False,
            enabled=True,
        )
        profile = ApiProfile(name="p", auth_required=True, auth_rejection_codes=[401, 403])
        resp = FakeResp(403, '{"status": 0, "message": "Your account is locked."}')
        status = _evaluate_status(tc, 403, resp, profile=profile)
        assert "Rejected with 403" in status
        assert "DEFECT" not in status


class TestProfileDrivenSkipping:
    def test_public_endpoint_skips_auth_tests(self, engine_env):
        profile = ApiProfile(
            name="public-register",
            auth_required=False,
            body_type="json",
            archetype="write",
        )
        results = run_suite(REGISTER_CURL, settings=_settings(), profile=profile)
        hdr1 = next(r for r in results if r.test_case_id == "HDR-001")
        assert hdr1.test_case_type == "Skipped"
        assert hdr1.status.startswith("N/A")

    def test_payload_tests_still_run_with_profile(self, engine_env):
        profile = ApiProfile(
            name="register",
            auth_required=True,
            body_type="json",
            archetype="write",
        )
        results = run_suite(REGISTER_CURL, settings=_settings(), profile=profile)
        assert any(r.test_case_id == "VAL-001" and r.test_case_type == "Validation" for r in results)

    def test_get_endpoint_skips_content_type_tests(self, engine_env):
        profile = ApiProfile(name="protected", auth_required=True, body_type="none")
        curl = (
            'curl -X GET http://localhost:5000/api/protected '
            '-H "Authorization: Bearer valid-token-12345"'
        )
        results = run_suite(curl, settings=_settings(), profile=profile)
        hdr4 = next(r for r in results if r.test_case_id == "HDR-004")
        assert hdr4.test_case_type == "Skipped"
        assert "no body" in hdr4.status


ITEMS_CURL = (
    'curl -X GET "http://localhost:5000/api/items?page=1&status=active" '
    '-H "Accept: application/json"'
)

ORDER_CURL = (
    'curl -X POST http://localhost:5000/api/order '
    '-H "Content-Type: application/json" '
    '-d \'{"product_id":"p1","amount":100}\''
)


class TestNewChecks:
    """GLB-004/005 (query params), GLB-007 (method), GLB-009 (security
    headers), GLB-013 (schema), GLB-015 (duplicate submit)."""

    def test_query_param_invalid_rejected(self, engine_env):
        profile = ApiProfile(
            name="items", auth_required=False, body_type="none",
            archetype="read_list", query_params=["page", "status"],
        )
        results = run_suite(ITEMS_CURL, settings=_settings(), profile=profile)
        glb4 = next(r for r in results if r.test_case_id == "GLB-004")
        assert "Rejected invalid query param" in glb4.status
        assert glb4.status_code == 400

    def test_query_param_sql_injection_rejected(self, engine_env):
        profile = ApiProfile(
            name="items", auth_required=False, body_type="none",
            archetype="read_list", query_params=["page", "status"],
        )
        results = run_suite(ITEMS_CURL, settings=_settings(), profile=profile)
        glb6 = next(r for r in results if r.test_case_id == "GLB-006")
        assert "Rejected" in glb6.status
        assert glb6.status_code == 400

    def test_security_headers_check_passes(self, engine_env):
        profile = ApiProfile(
            name="items", auth_required=False, body_type="none",
            archetype="read_list", query_params=["page", "status"],
        )
        results = run_suite(ITEMS_CURL, settings=_settings(), profile=profile)
        glb9 = next(r for r in results if r.test_case_id == "GLB-009")
        assert "Security headers present" in glb9.status

    def test_schema_validation_passes(self, engine_env):
        profile = ApiProfile(
            name="items", auth_required=False, body_type="none",
            archetype="read_list", query_params=["page", "status"],
            response_schema={"success": "int", "message": "string", "data": "list"},
        )
        results = run_suite(ITEMS_CURL, settings=_settings(), profile=profile)
        glb13 = next(r for r in results if r.test_case_id == "GLB-013")
        assert "Schema validated" in glb13.status

    def test_duplicate_submit_detects_rejection(self, engine_env):
        profile = ApiProfile(
            name="order", auth_required=False, body_type="json",
            archetype="write", idempotency_required=True, idempotency_key="order_ref",
        )
        results = run_suite(ORDER_CURL, settings=_settings(), profile=profile)
        glb15 = next(r for r in results if r.test_case_id == "GLB-015")
        assert "duplicate rejected" in glb15.status
        assert glb15.status_code == 409

    def test_duplicate_submit_skipped_without_idempotency(self, engine_env):
        profile = ApiProfile(
            name="order-plain", auth_required=False, body_type="json", archetype="write",
        )
        results = run_suite(ORDER_CURL, settings=_settings(), profile=profile)
        glb15 = next(r for r in results if r.test_case_id == "GLB-015")
        assert glb15.test_case_type == "Skipped"


class TestBuiltinUniversalSuite:
    """The built-in suite (W1-W14 check points) must always run for every API,
    even without a test case bank or when the bank omits/disables checks."""

    def _custom_bank(self, tmp_path, with_glb15_disabled=False):
        import openpyxl
        path = tmp_path / "custom_bank.xlsx"
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["TestCaseID", "Scope", "TestCaseType", "Description",
                   "MutationType", "MutationValue", "ExpectedStatusCodeRange",
                   "ExpectedBehavior", "AppliesToMandatoryOnly", "Enabled"])
        ws.append(["CUSTOM-001", "Global", "Validation", "Custom check",
                   "baseline", "", "200-200", "Custom", "FALSE", "TRUE"])
        if with_glb15_disabled:
            ws.append(["GLB-015", "Global", "Validation",
                       "Duplicate submission prevention", "duplicate_submit",
                       "", "400-499", "Duplicate payloads should be rejected",
                       "FALSE", "FALSE"])
        wb.save(path)
        return str(path)

    def test_builtin_suite_runs_without_bank(self, engine_env, monkeypatch):
        import pathlib
        real_exists = pathlib.Path.exists

        def fake_exists(self):
            if str(self).endswith("default_test_cases.xlsx"):
                return False
            return real_exists(self)

        monkeypatch.setattr(pathlib.Path, "exists", fake_exists)
        results = run_suite(REGISTER_CURL, settings=_settings())
        ids = {r.test_case_id for r in results}
        assert {"HDR-001", "VAL-001", "VAL-018",
                "GLB-001", "GLB-003", "GLB-006", "GLB-009", "GLB-015"} <= ids

    def test_builtin_checks_merge_with_bank(self, engine_env, tmp_path):
        results = run_suite(REGISTER_CURL, settings=_settings(),
                            test_case_file=self._custom_bank(tmp_path))
        ids = {r.test_case_id for r in results}
        assert "CUSTOM-001" in ids
        assert "GLB-015" in ids

    def test_builtin_wins_over_disabled_bank_row(self, engine_env, tmp_path):
        results = run_suite(REGISTER_CURL, settings=_settings(),
                            test_case_file=self._custom_bank(tmp_path, with_glb15_disabled=True))
        glb15 = next(r for r in results if r.test_case_id == "GLB-015")
        assert glb15.test_case_type == "Validation"
        assert not glb15.status.startswith("N/A")


class TestRateLimitPause:
    """429 / IP-block responses pause the run when a handler is provided,
    and degrade to warn + Retry-After sleep without one."""

    def _block_all(self, monkeypatch, status_code=429, body="Too Many Requests", headers=None):
        import requests

        def blocked(method, url, timeout=None, **kwargs):
            return FakeResponse(status_code, body, headers or {})

        monkeypatch.setattr(requests, "request", blocked)

    def test_429_pause_resume_continues(self, engine_env, monkeypatch):
        self._block_all(monkeypatch)
        prompts = []

        def on_rate_limit(resp, consecutive):
            prompts.append((resp.status_code, consecutive))
            return "resume", None

        results = run_suite(REGISTER_CURL, settings=_settings(), on_rate_limit=on_rate_limit)
        assert prompts, "pause callback must be invoked on 429"
        assert all(code == 429 for code, _ in prompts)
        assert results, "run continues after resume"

    def test_429_pause_cancel_stops_run(self, engine_env, monkeypatch):
        import threading
        self._block_all(monkeypatch)
        cancel_event = threading.Event()

        def on_rate_limit(resp, consecutive):
            return "cancel", None

        results = run_suite(REGISTER_CURL, settings=_settings(),
                            cancel_event=cancel_event, on_rate_limit=on_rate_limit)
        assert cancel_event.is_set()
        assert len(results) == 1, "header loop must stop right after the cancel"

    def test_403_block_marker_detection(self):
        from src.rate_limit import is_block_response
        assert is_block_response(FakeResponse(429, "Too Many Requests"))
        assert is_block_response(FakeResponse(403, "Access denied: rate limiting active"))
        assert is_block_response(FakeResponse(403, "Your IP has been blocked"))
        assert not is_block_response(FakeResponse(403, "Forbidden - invalid token"))
        assert not is_block_response(FakeResponse(401, "too many requests"))
        assert not is_block_response(FakeResponse(500, "blocked"))

    def test_ip_already_blocked_detected_on_any_status(self):
        from src.rate_limit import is_block_response
        assert is_block_response(FakeResponse(
            401, '{"message":"IP Already blocked","statusCode":"403","success":0}'))
        assert is_block_response(FakeResponse(200, '{"message":"IP Already blocked"}'))
        assert is_block_response(FakeResponse(200, "ip already blocked"))
        assert not is_block_response(FakeResponse(200, '{"message":"Account already blocked"}'))

    def test_no_callback_sleeps_and_continues(self, engine_env, monkeypatch):
        self._block_all(monkeypatch, headers={"Retry-After": "1"})
        sleeps = []
        import time as time_mod
        monkeypatch.setattr(time_mod, "sleep", lambda s: sleeps.append(s))
        results = run_suite(REGISTER_CURL, settings=_settings())
        assert sleeps, "headless path must sleep before continuing"
        assert max(sleeps) <= 1.0 + 1e-9, "Retry-After value must be honored (capped)"
        assert results, "run continues after the wait"

    def test_delay_increase_applied_to_subsequent_sleeps(self, engine_env, monkeypatch):
        self._block_all(monkeypatch)
        sleeps = []
        import time as time_mod
        monkeypatch.setattr(time_mod, "sleep", lambda s: sleeps.append(s))
        settings = _settings()

        def on_rate_limit(resp, consecutive):
            return "resume", 2000

        run_suite(REGISTER_CURL, settings=settings, on_rate_limit=on_rate_limit)
        assert settings.request_delay_ms == 2000
        assert any(s >= 2.0 for s in sleeps), "post-pause sleeps must use the new delay"

    def test_decide_prompt_action(self):
        from src.rate_limit import decide_prompt_action
        assert decide_prompt_action("", 500) == ("resume", None)
        assert decide_prompt_action("r", 500) == ("resume", None)
        assert decide_prompt_action("resume", 500) == ("resume", None)
        assert decide_prompt_action("d", 500) == ("resume", 1000)
        assert decide_prompt_action("double", 500) == ("resume", 1000)
        assert decide_prompt_action("2000", 500) == ("resume", 2000)
        assert decide_prompt_action("c", 500) == ("cancel", None)
        assert decide_prompt_action("cancel", 500) == ("cancel", None)
        assert decide_prompt_action("garbage", 500) == ("invalid", None)
        assert decide_prompt_action("-5", 500) == ("invalid", None)


class _SignalingController:
    """PauseController that signals when the worker first reaches the pause."""

    def __init__(self, *args, **kwargs):
        from src.pause_controller import PauseController
        self._inner = PauseController(*args, **kwargs)
        self.entered_pause = threading.Event()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def wait_if_paused(self, cancel_event=None, timeout=0.2):
        if self._inner.is_paused():
            self.entered_pause.set()
        return self._inner.wait_if_paused(cancel_event, timeout)


class TestPauseResume:
    """Cooperative pause between requests: the run blocks, the payload and
    settings can be swapped, and it resumes in place."""

    def test_swap_payload_and_settings_mid_run(self, engine_env, monkeypatch):
        import requests
        from src.curl_parser import parse_curl

        # Wrap the (fixture-patched) request fn to record the bodies sent
        real_request = requests.request
        recorded = []

        def recording(method, url, timeout=None, **kwargs):
            payload = kwargs.get("json")
            if payload is None:
                payload = kwargs.get("data")
            recorded.append((method, url, payload))
            return real_request(method, url, timeout=timeout, **kwargs)

        monkeypatch.setattr(requests, "request", recording)

        sleeps = []
        monkeypatch.setattr(time_mod, "sleep", lambda s: sleeps.append(s))

        settings = Settings(request_delay_ms=0, timeout_seconds=5, max_retries=1)
        controller = _SignalingController(settings=settings)
        controller.pause()

        outcomes = []

        def run():
            outcomes.append(run_suite(REGISTER_CURL, settings=settings,
                                      pause_controller=controller))

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert controller.entered_pause.wait(timeout=10), "worker never reached the pause"

        # Swap the payload (extra field) and bump the delay while paused
        new_curl = REGISTER_CURL.replace(
            '"password":"secret123"', '"password":"secret123","nickname":"nicky"'
        )
        new_parsed = parse_curl(new_curl)
        settings.request_delay_ms = 50
        controller.update(parsed=new_parsed)
        controller.resume()

        t.join(timeout=60)
        assert not t.is_alive(), "run did not finish after resume"
        results = outcomes[0]
        assert results, "run must produce results after resume"

        bodies = [p for (_m, _u, p) in recorded if isinstance(p, dict)]
        assert any("nickname" in p for p in bodies), \
            "post-resume requests must use the swapped payload"
        assert any(abs(s - 0.05) < 0.01 for s in sleeps), \
            "post-resume sleeps must use the new delay"

    def test_cancel_while_paused_aborts(self, engine_env, monkeypatch):
        settings = Settings(request_delay_ms=0, timeout_seconds=5, max_retries=1)
        cancel_event = threading.Event()
        controller = _SignalingController(settings=settings)
        controller.pause()

        outcomes = []

        def run():
            outcomes.append(run_suite(REGISTER_CURL, settings=settings,
                                      cancel_event=cancel_event,
                                      pause_controller=controller))

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert controller.entered_pause.wait(timeout=10), "worker never reached the pause"

        cancel_event.set()
        t.join(timeout=30)
        assert not t.is_alive(), "run did not stop after cancel while paused"
        assert outcomes[0] == [], "no tests may run after a cancel while paused"


class TestPerTestLogging:
    """Each test case must emit an INFO log line for the console/GUI."""

    def test_each_testcase_logged(self, engine_env, caplog):
        with caplog.at_level(logging.INFO, logger="src.test_engine"):
            results = run_suite(REGISTER_CURL, settings=_settings())
        text = caplog.text
        assert results
        assert "[GLB-001]" in text, "global test must be logged"
        assert "[HDR-001]" in text, "header test must be logged"
        assert "[VAL-001]" in text, "payload test must be logged"
        assert "key=" in text, "log lines must carry the target key"

    def test_mandatory_detection_logs_each_key(self, engine_env, caplog):
        with caplog.at_level(logging.INFO, logger="src.mandatory_detector"):
            run_suite(REGISTER_CURL, settings=_settings())
        text = caplog.text
        assert "mandatory=" in text, "each mandatory probe must be logged"
        assert "key=username" in text or "key=email" in text or "key=password" in text