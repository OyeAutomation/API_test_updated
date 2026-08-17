import pytest
from src.payload_mutator import (
    apply_mutation,
    is_header_mutation,
    MUTATION_DISPATCH,
    MutationType,
)


@pytest.fixture
def sample_payload():
    return {
        "username": "john_doe",
        "email": "john@test.com",
        "age": 25,
        "is_active": True,
        "tags": ["user", "premium"],
        "address": {
            "street": "123 Main St",
            "zip": "12345",
            "country": "US",
        },
    }


def test_remove_key(sample_payload):
    result = apply_mutation(sample_payload, MutationType.REMOVE_KEY, "username")
    assert "username" not in result
    assert result["email"] == "john@test.com"


def test_remove_nested_key(sample_payload):
    result = apply_mutation(sample_payload, MutationType.REMOVE_KEY, "address.zip")
    assert "zip" not in result["address"]
    assert result["address"]["street"] == "123 Main St"


def test_empty_value(sample_payload):
    result = apply_mutation(sample_payload, MutationType.EMPTY_VALUE, "username")
    assert result["username"] == ""


def test_null_value(sample_payload):
    result = apply_mutation(sample_payload, MutationType.NULL_VALUE, "email")
    assert result["email"] is None


def test_alpha_only(sample_payload):
    result = apply_mutation(sample_payload, MutationType.ALPHA_ONLY, "username")
    assert result["username"] == "abcdefGHIJKL"


def test_numeric_only(sample_payload):
    result = apply_mutation(sample_payload, MutationType.NUMERIC_ONLY, "age")
    assert result["age"] == "1234567890"


def test_special_chars(sample_payload):
    result = apply_mutation(sample_payload, MutationType.SPECIAL_CHARS, "username")
    assert "!" in result["username"] or "@" in result["username"]


def test_sql_injection(sample_payload):
    result = apply_mutation(sample_payload, MutationType.SQL_INJECTION, "username")
    assert " OR " in result["username"] or "1'='1" in result["username"]


def test_xss_payload(sample_payload):
    result = apply_mutation(sample_payload, MutationType.XSS_PAYLOAD, "username")
    assert "<script>" in result["username"]


def test_max_length_exceed(sample_payload):
    result = apply_mutation(sample_payload, MutationType.MAX_LENGTH_EXCEED, "username")
    assert len(result["username"]) == 10000


def test_unicode_emoji(sample_payload):
    result = apply_mutation(sample_payload, MutationType.UNICODE_EMOJI, "username")
    assert "👋" in result["username"]


def test_wrong_type_string_to_int(sample_payload):
    result = apply_mutation(sample_payload, MutationType.WRONG_TYPE, "age")
    assert result["age"] == "not_an_integer"


def test_wrong_type_int_to_string(sample_payload):
    result = apply_mutation(sample_payload, MutationType.WRONG_TYPE, "username")
    assert result["username"] == 12345


def test_is_header_mutation():
    assert is_header_mutation(MutationType.HEADER_MISSING)
    assert is_header_mutation(MutationType.HEADER_INVALID_VALUE)
    assert is_header_mutation(MutationType.AUTH_TOKEN_MISSING)
    assert is_header_mutation(MutationType.AUTH_TOKEN_INVALID)
    assert is_header_mutation(MutationType.AUTH_TOKEN_EXPIRED)
    assert not is_header_mutation(MutationType.REMOVE_KEY)
    assert not is_header_mutation(MutationType.XSS_PAYLOAD)


def test_all_mutation_types_present():
    """Every MutationType should have a handler."""
    for mt in MutationType:
        assert mt in MUTATION_DISPATCH, f"Missing handler for {mt}"


def test_oversized_payload(sample_payload):
    result = apply_mutation(sample_payload, MutationType.OVERSIZED_PAYLOAD, "username")
    assert len(result["username"]) == 50000


def test_min_length_violate(sample_payload):
    result = apply_mutation(sample_payload, MutationType.MIN_LENGTH_VIOLATE, "username")
    assert result["username"] == ""


def test_header_missing_mutation():
    result = apply_mutation({}, MutationType.HEADER_MISSING, "", "Authorization")
    assert result["_header_action"] == "remove"
    assert result["_header_key"] == "Authorization"


def test_header_invalid_value():
    result = apply_mutation({}, MutationType.HEADER_INVALID_VALUE, "", "Content-Type:text/plain")
    assert result["_header_action"] == "modify"


def test_auth_token_invalid():
    result = apply_mutation({}, MutationType.AUTH_TOKEN_INVALID, "")
    assert result["_header_action"] == "modify"
    assert "Authorization" in result["_header_spec"]
