from __future__ import annotations
import copy
import json
import logging
from typing import Optional

import requests

from src.models import ParsedRequest, MutationType
from src.curl_parser import curl_to_requests_kwargs
from src.crypto_adapter import CryptoAdapter
from src.payload_mutator import apply_mutation, is_header_mutation

logger = logging.getLogger(__name__)


CHECK_MUTATION_TYPES = (
    MutationType.SECURITY_HEADERS_CHECK,
    MutationType.CORS_CHECK,
    MutationType.SENSITIVE_DATA_SCAN,
    MutationType.ERROR_LEAK_SCAN,
    MutationType.SCHEMA_VALIDATION,
    MutationType.PERFORMANCE_CHECK,
    MutationType.DUPLICATE_SUBMIT,
)


def _is_check_mutation(mutation_type: MutationType) -> bool:
    return mutation_type in CHECK_MUTATION_TYPES


def build_mutated_request(
    parsed: ParsedRequest,
    key_path: str,
    mutation_type: MutationType,
    mutation_value: Optional[str] = None,
    crypto_adapter: Optional[CryptoAdapter] = None,
) -> dict:
    """Build a requests kwargs dict with a mutation applied to the given key.

    When crypto_adapter is in checksum_field mode, the mutation is applied to
    the decrypted inner payload, then re-encrypted into the checksum wrapper.
    """
    base_kwargs = curl_to_requests_kwargs(parsed)

    checksum_mode = crypto_adapter is not None and crypto_adapter.has_checksum_mode()
    full_body_mode = (
        not checksum_mode
        and crypto_adapter is not None
        and crypto_adapter.profile is not None
    )

    if is_header_mutation(mutation_type):
        result = apply_mutation({}, mutation_type, key_path, mutation_value)
        action = result.get("_header_action")
        if action == "remove":
            header_key = result.get("_header_key", "Authorization")
            headers = dict(base_kwargs.get("headers", {}))
            headers.pop(header_key, None)
            base_kwargs["headers"] = headers
        elif action == "modify":
            header_spec = result.get("_header_spec", "")
            if ":" in header_spec:
                h_key, h_val = header_spec.split(":", 1)
                headers = dict(base_kwargs.get("headers", {}))
                headers[h_key.strip()] = h_val.strip()
                base_kwargs["headers"] = headers
        if full_body_mode and parsed.body_raw:
            base_kwargs["_skip_encrypt"] = True
    elif mutation_type in (MutationType.QUERY_PARAM_INVALID, MutationType.QUERY_PARAM_INJECT):
        result = apply_mutation({}, mutation_type, key_path, mutation_value)
        params = dict(base_kwargs.get("params", {}))
        params[result.get("_query_key", "page")] = result.get("_query_value", "-1")
        base_kwargs["params"] = params
    elif mutation_type == MutationType.METHOD_CHANGE:
        result = apply_mutation({}, mutation_type, key_path, mutation_value)
        base_kwargs["method"] = result.get("_method", "DELETE")
        if full_body_mode and parsed.body_raw:
            base_kwargs["_skip_encrypt"] = True
    elif _is_check_mutation(mutation_type):
        # Response-level checks: send the original request (with optional
        # modifications handled below); the engine inspects the response
        # headers/body/timing.
        if mutation_type == MutationType.CORS_CHECK:
            headers = dict(base_kwargs.get("headers", {}))
            headers["Origin"] = mutation_value or "https://evil.example.com"
            base_kwargs["headers"] = headers
        elif mutation_type == MutationType.ERROR_LEAK_SCAN:
            base_kwargs.pop("json", None)
            base_kwargs["data"] = '{"invalid_json: }'
            base_kwargs["_skip_encrypt"] = True
        elif full_body_mode and parsed.body_raw:
            # Encrypted raw body: send the original encrypted payload as-is
            base_kwargs["_skip_encrypt"] = True
    else:
        # Payload mutation
        if parsed.body_json is not None:
            if checksum_mode:
                inner_json = crypto_adapter.decrypt_body_json(parsed.body_json)
                if inner_json is parsed.body_json:
                    base_json = copy.deepcopy(parsed.body_json)
                    mutated = apply_mutation(base_json, mutation_type, key_path, mutation_value)
                    base_kwargs.pop("data", None)
                    _set_mutated_body(base_kwargs, mutated)
                else:
                    mutated_inner = apply_mutation(inner_json, mutation_type, key_path, mutation_value)
                    if "_malformed_json" in mutated_inner:
                        base_kwargs.pop("json", None)
                        base_kwargs["data"] = mutated_inner["_malformed_json"]
                        base_kwargs["_decrypted_payload"] = mutated_inner["_malformed_json"]
                        base_kwargs["_skip_encrypt"] = True
                    else:
                        base_kwargs["_decrypted_payload"] = json.dumps(mutated_inner)
                        wrapped = crypto_adapter.encrypt_body_json(parsed.body_json, mutated_inner)
                        base_kwargs["json"] = wrapped
                        base_kwargs.pop("data", None)
            else:
                base_json = copy.deepcopy(parsed.body_json)
                mutated = apply_mutation(base_json, mutation_type, key_path, mutation_value)
                base_kwargs.pop("data", None)
                _set_mutated_body(base_kwargs, mutated)
        elif full_body_mode and parsed.body_raw:
            # Full-body encryption: body is raw encrypted string (text/plain)
            try:
                inner_str = crypto_adapter.decrypt_payload(parsed.body_raw)
                inner_json = json.loads(inner_str)
                mutated_inner = apply_mutation(inner_json, mutation_type, key_path, mutation_value)
                base_kwargs["_decrypted_payload"] = json.dumps(mutated_inner)
                base_kwargs["data"] = crypto_adapter.encrypt_payload(mutated_inner)
                base_kwargs["_skip_encrypt"] = True
            except Exception as e:
                logger.warning(f"Full-body encryption failed: {e}")
                base_kwargs["data"] = parsed.body_raw

    return base_kwargs


def _set_mutated_body(base_kwargs: dict, mutated: dict) -> None:
    """Write a mutated payload into kwargs, translating the malformed-JSON
    sentinel into a raw data body."""
    if "_malformed_json" in mutated:
        base_kwargs.pop("json", None)
        base_kwargs["data"] = mutated["_malformed_json"]
        base_kwargs["_decrypted_payload"] = mutated["_malformed_json"]
        base_kwargs["_skip_encrypt"] = True
    else:
        base_kwargs["json"] = mutated
        base_kwargs["_decrypted_payload"] = json.dumps(mutated)


def send_request(
    kwargs: dict,
    crypto_adapter: Optional[CryptoAdapter] = None,
    timeout: int = 30,
    rate_guard=None,
) -> requests.Response:
    """Send an HTTP request using the given kwargs dict, with optional crypto."""
    method = kwargs.pop("method", "POST")
    url = kwargs.pop("url")
    headers = dict(kwargs.get("headers", {}))

    checksum_mode = crypto_adapter is not None and crypto_adapter.has_checksum_mode()

    # Capture the payload that will actually be sent
    encrypted_payload = ""
    if "json" in kwargs:
        encrypted_payload = json.dumps(kwargs["json"])
    elif "data" in kwargs:
        encrypted_payload = str(kwargs["data"])

    # Encrypt body if crypto is active and not already encrypted (non-checksum mode)
    skip = kwargs.pop("_skip_encrypt", False)
    if not checksum_mode and crypto_adapter and crypto_adapter.profile is not None and not skip:
        json_data = kwargs.pop("json", None)
        if json_data is not None:
            encrypted = crypto_adapter.encrypt_payload(json_data)
            encrypted_payload = encrypted
            kwargs["data"] = encrypted
            headers["Content-Type"] = "application/jose"
        else:
            data_val = kwargs.get("data")
            if data_val and isinstance(data_val, str):
                encrypted = crypto_adapter.encrypt_payload(data_val)
                encrypted_payload = encrypted
                kwargs["data"] = encrypted
                headers["Content-Type"] = "application/jose"

    kwargs["headers"] = headers

    resp = requests.request(method=method, url=url, timeout=timeout, **kwargs)
    resp._encrypted_payload = encrypted_payload

    # Decrypt response only if it looks like encrypted data
    if crypto_adapter and crypto_adapter.profile is not None:
        ct = resp.headers.get("Content-Type", "")
        is_encrypted_ct = "jose" in ct.lower()
        if not is_encrypted_ct and not crypto_adapter.has_checksum_mode():
            is_encrypted_ct = crypto_adapter.profile.salt_from_data
        if is_encrypted_ct:
            try:
                decrypted = crypto_adapter.decrypt_payload(resp.text)
                resp._crypto_decrypted = decrypted
            except Exception:
                pass
        elif not crypto_adapter.has_checksum_mode():
            # Full-body mode: server may serve encrypted data as application/json.
            # Attempt decryption and only accept it if the result parses as JSON.
            try:
                decrypted = crypto_adapter.decrypt_payload(resp.text)
                json.loads(decrypted)
                resp._crypto_decrypted = decrypted
            except Exception:
                pass
        # Also try checksum-field decryption on response body
        # Save and restore _checksum_format to avoid corrupting adapter state
        saved_format = getattr(crypto_adapter, '_checksum_format', None)
        if crypto_adapter.profile is not None and (
            crypto_adapter.has_checksum_mode() or crypto_adapter.response_profile is not None
        ):
            try:
                resp_body = resp.json()
                if isinstance(resp_body, dict):
                    inner = crypto_adapter.decrypt_response_json(resp_body)
                    if inner is not resp_body:
                        resp._crypto_decrypted = json.dumps(inner)
            except Exception:
                pass
        crypto_adapter._checksum_format = saved_format

    if rate_guard is not None:
        rate_guard.check(resp)

    return resp