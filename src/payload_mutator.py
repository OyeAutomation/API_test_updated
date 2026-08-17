from __future__ import annotations
import copy
import random
import string
from typing import Any, Dict, Optional, Callable

from src.models import MutationType

# Payload mutation functions dispatch table
# Each function takes (payload: dict, key_path: str, mutation_value: Optional[str])
# and returns a new mutated dict (shallow copy modified).


def _set_nested_value(payload: dict, key_path: str, value: Any) -> dict:
    """Set a value at a dot-path key in a nested dict. Returns new dict."""
    result = copy.deepcopy(payload)
    parts = key_path.split(".")
    current = result
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value
    return result


def _delete_nested_key(payload: dict, key_path: str) -> dict:
    """Delete a key at dot-path. Returns new dict."""
    result = copy.deepcopy(payload)
    parts = key_path.split(".")
    current = result
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            return result
        current = current[part]
    current.pop(parts[-1], None)
    return result


def _get_nested_value(payload: dict, key_path: str) -> Any:
    """Get a value at dot-path."""
    parts = key_path.split(".")
    current = payload
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _get_original_type(payload: dict, key_path: str) -> type:
    val = _get_nested_value(payload, key_path)
    if val is None:
        return str
    return type(val)


def mutate_remove_key(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    return _delete_nested_key(payload, key_path)


def mutate_empty_value(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    return _set_nested_value(payload, key_path, "")


def mutate_null_value(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    return _set_nested_value(payload, key_path, None)


def mutate_alpha_only(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "abcdefGHIJKL"
    return _set_nested_value(payload, key_path, val)


def mutate_numeric_only(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "1234567890"
    return _set_nested_value(payload, key_path, val)


def mutate_special_chars(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "!@#$%^&*()_+{}|:\"<>?~"
    return _set_nested_value(payload, key_path, val)


def mutate_max_length_exceed(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    # 10,000 char string
    val = value or "A" * 10000
    return _set_nested_value(payload, key_path, val)


def mutate_min_length_violate(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    return _set_nested_value(payload, key_path, "")


def mutate_sql_injection(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "' OR '1'='1"
    return _set_nested_value(payload, key_path, val)


def mutate_xss_payload(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "<script>alert('xss')</script>"
    return _set_nested_value(payload, key_path, val)


def mutate_oversized_payload(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "A" * 50000
    return _set_nested_value(payload, key_path, val)


def mutate_unicode_emoji(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    val = value or "Hello World 👋🔥💯"
    return _set_nested_value(payload, key_path, val)


def mutate_wrong_type(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    orig_type = _get_original_type(payload, key_path)
    if orig_type == int:
        val = "not_an_integer"
    elif orig_type == float:
        val = "not_a_float"
    elif orig_type == bool:
        val = "not_a_bool"
    elif orig_type == list:
        val = "not_a_list"
    elif orig_type == dict:
        val = "not_an_object"
    else:
        val = 12345  # number into string field
    return _set_nested_value(payload, key_path, val)


def mutate_header_missing(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    """For header mutations, we return the header info via the payload dict."""
    return {"_header_action": "remove", "_header_key": key_path or value or "Authorization"}


def mutate_header_invalid_value(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    header_info = value or "Content-Type:text/plain"
    return {"_header_action": "modify", "_header_spec": header_info}


def mutate_auth_token_missing(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    return {"_header_action": "remove", "_header_key": "Authorization"}


def mutate_auth_token_invalid(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    token = value or "Bearer invalid_token_12345"
    return {"_header_action": "modify", "_header_spec": f"Authorization:{token}"}


def mutate_auth_token_expired(payload: dict, key_path: str, value: Optional[str] = None) -> dict:
    token = value or "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9"
    return {"_header_action": "modify", "_header_spec": f"Authorization:{token}"}


MUTATION_DISPATCH: Dict[MutationType, Callable] = {
    MutationType.REMOVE_KEY: mutate_remove_key,
    MutationType.EMPTY_VALUE: mutate_empty_value,
    MutationType.NULL_VALUE: mutate_null_value,
    MutationType.ALPHA_ONLY: mutate_alpha_only,
    MutationType.NUMERIC_ONLY: mutate_numeric_only,
    MutationType.SPECIAL_CHARS: mutate_special_chars,
    MutationType.MAX_LENGTH_EXCEED: mutate_max_length_exceed,
    MutationType.MIN_LENGTH_VIOLATE: mutate_min_length_violate,
    MutationType.SQL_INJECTION: mutate_sql_injection,
    MutationType.XSS_PAYLOAD: mutate_xss_payload,
    MutationType.OVERSIZED_PAYLOAD: mutate_oversized_payload,
    MutationType.UNICODE_EMOJI: mutate_unicode_emoji,
    MutationType.WRONG_TYPE: mutate_wrong_type,
    MutationType.HEADER_MISSING: mutate_header_missing,
    MutationType.HEADER_INVALID_VALUE: mutate_header_invalid_value,
    MutationType.AUTH_TOKEN_MISSING: mutate_auth_token_missing,
    MutationType.AUTH_TOKEN_INVALID: mutate_auth_token_invalid,
    MutationType.AUTH_TOKEN_EXPIRED: mutate_auth_token_expired,
}


def apply_mutation(
    payload: dict,
    mutation_type: MutationType,
    key_path: str,
    mutation_value: Optional[str] = None,
) -> dict:
    """Apply a mutation to a payload and return the new dict."""
    func = MUTATION_DISPATCH.get(mutation_type)
    if func is None:
        raise ValueError(f"Unknown mutation type: {mutation_type}")
    return func(payload, key_path, mutation_value)


def is_header_mutation(mutation_type: MutationType) -> bool:
    return mutation_type in (
        MutationType.HEADER_MISSING,
        MutationType.HEADER_INVALID_VALUE,
        MutationType.AUTH_TOKEN_MISSING,
        MutationType.AUTH_TOKEN_INVALID,
        MutationType.AUTH_TOKEN_EXPIRED,
    )
