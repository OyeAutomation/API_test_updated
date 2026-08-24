import pytest

from src.curl_parser import parse_curl
from src.models import MutationType, ParsedRequest
from src.request_builder import build_mutated_request


CURL = (
    'curl -X POST https://api.example.com/register '
    '-H "Content-Type: application/json" '
    '-d \'{"username":"john","password":"secret123"}\''
)


def _parsed() -> ParsedRequest:
    return parse_curl(CURL)


def test_malformed_json_mutation_sets_raw_data_body():
    kwargs = build_mutated_request(_parsed(), "", MutationType.MALFORMED_JSON, "{broken json")
    assert "json" not in kwargs
    assert kwargs["data"] == "{broken json"
    assert kwargs["_decrypted_payload"] == "{broken json"


def test_malformed_json_default_value():
    kwargs = build_mutated_request(_parsed(), "", MutationType.MALFORMED_JSON)
    assert "json" not in kwargs
    assert kwargs["data"].startswith('{"username":')


def test_full_body_decrypt_failure_does_not_crash():
    """Regression: the full-body encryption error path used to raise
    NameError (logger was never imported)."""

    class BrokenAdapter:
        def __init__(self):
            self.profile = object()  # non-None, no checksum mode

        def has_checksum_mode(self):
            return False

        def decrypt_payload(self, ciphertext):
            raise ValueError("boom")

        def encrypt_payload(self, data):
            raise ValueError("boom")

    parsed = parse_curl(
        'curl -X POST https://api.example.com/x '
        '-H "Content-Type: text/plain" '
        '-d "U2FsdGVkX1+encryptedbody"'
    )
    kwargs = build_mutated_request(parsed, "username", MutationType.EMPTY_VALUE,
                                   crypto_adapter=BrokenAdapter())
    # Graceful fallback: the raw body is sent as-is, no exception raised
    assert kwargs["data"] == "U2FsdGVkX1+encryptedbody"


def test_basic_payload_mutation():
    kwargs = build_mutated_request(_parsed(), "username", MutationType.EMPTY_VALUE)
    assert kwargs["json"]["username"] == ""
    assert kwargs["json"]["password"] == "secret123"


def test_header_missing_mutation():
    kwargs = build_mutated_request(_parsed(), "", MutationType.HEADER_MISSING, "Authorization")
    assert "Authorization" not in kwargs["headers"]