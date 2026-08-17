import pytest
from unittest.mock import patch, MagicMock
import requests
from src.mandatory_detector import detect_mandatory_fields, _get_all_keys, _is_validation_error
from src.models import ParsedRequest, HttpMethod, Settings
from src.crypto_adapter import CryptoAdapter


class MockResponse:
    def __init__(self, status_code, text, json_data=None):
        self.status_code = status_code
        self._text = text
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        import json
        return json.loads(self._text)

    @property
    def text(self):
        return self._text


def test_get_all_keys_flat():
    data = {"a": 1, "b": 2, "c": 3}
    keys = _get_all_keys(data)
    assert set(keys) == {"a", "b", "c"}


def test_get_all_keys_nested():
    data = {"a": 1, "b": {"c": 2, "d": {"e": 3}}}
    keys = _get_all_keys(data, max_depth=3)
    assert "a" in keys
    assert "b" in keys
    assert "b.c" in keys
    assert "b.d" in keys
    assert "b.d.e" in keys


def test_is_validation_error():
    assert _is_validation_error("Field is required", ["required", "missing"])
    assert _is_validation_error("Missing parameter", ["required", "missing"])
    assert _is_validation_error("Mandatory field not found", ["required", "missing", "mandatory"])
    assert not _is_validation_error("Success", ["required", "missing", "mandatory"])
    assert _is_validation_error("field is REQUIRED", ["required"])


def test_get_all_keys_depth_limit():
    data = {"a": {"b": {"c": {"d": {"e": 5}}}}}
    keys = _get_all_keys(data, max_depth=2)
    assert "a" in keys
    assert "a.b" in keys
    assert "a.b.c" in keys


@patch("requests.request")
def test_detect_mandatory_missing_key(mock_request):
    """Test that removing a required key shifts status code to 4xx."""
    parsed = ParsedRequest(
        method=HttpMethod.POST,
        url="http://test.com/api",
        headers={"Content-Type": "application/json"},
        body_json={"username": "john", "email": "john@test.com"},
    )

    # Baseline returns 200; removing username returns 400; removing email returns 200
    mock_request.side_effect = [
        MockResponse(200, '{"message":"ok"}', {"message": "ok"}),
        MockResponse(400, '{"error":"Missing required field: username"}', {"error": "Missing required field: username"}),
        MockResponse(200, '{"message":"ok"}', {"message": "ok"}),
    ]

    settings = Settings(request_delay_ms=0)
    results = detect_mandatory_fields(parsed, settings)

    assert "username" in results
    assert results["username"].is_mandatory is True
    assert "email" in results
    assert results["email"].is_mandatory is False


@patch("requests.request")
def test_detect_mandatory_no_body(mock_request):
    """Test that GET requests with no body skip mandatory detection."""
    parsed = ParsedRequest(
        method=HttpMethod.GET,
        url="http://test.com/api",
        headers={},
    )
    settings = Settings(request_delay_ms=0)
    results = detect_mandatory_fields(parsed, settings)
    assert results == {}


@patch("requests.request")
def test_detect_mandatory_all_optional(mock_request):
    """Test when all fields are optional - baseline is 200 and removals still 200."""
    parsed = ParsedRequest(
        method=HttpMethod.POST,
        url="http://test.com/api",
        headers={"Content-Type": "application/json"},
        body_json={"name": "test", "desc": "hello"},
    )

    mock_request.side_effect = [
        MockResponse(200, '{"message":"ok"}'),
        MockResponse(200, '{"message":"ok"}'),
        MockResponse(200, '{"message":"ok"}'),
    ]

    settings = Settings(request_delay_ms=0)
    results = detect_mandatory_fields(parsed, settings)
    assert results["name"].is_mandatory is False
    assert results["desc"].is_mandatory is False
