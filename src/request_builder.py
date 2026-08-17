from __future__ import annotations
import copy
import json
from typing import Any, Dict, Optional

import requests

from src.models import ParsedRequest, MutationType
from src.curl_parser import curl_to_requests_kwargs
from src.crypto_adapter import CryptoAdapter
from src.payload_mutator import apply_mutation, is_header_mutation


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
    else:
        # Payload mutation
        if parsed.body_json is not None:
            if checksum_mode:
                inner_json = crypto_adapter.decrypt_body_json(parsed.body_json)
                if inner_json is parsed.body_json:
                    base_json = copy.deepcopy(parsed.body_json)
                    mutated = apply_mutation(base_json, mutation_type, key_path, mutation_value)
                    base_kwargs["json"] = mutated
                    base_kwargs["_decrypted_payload"] = json.dumps(mutated)
                    base_kwargs.pop("data", None)
                else:
                    mutated_inner = apply_mutation(inner_json, mutation_type, key_path, mutation_value)
                    base_kwargs["_decrypted_payload"] = json.dumps(mutated_inner)
                    wrapped = crypto_adapter.encrypt_body_json(parsed.body_json, mutated_inner)
                    base_kwargs["json"] = wrapped
                    base_kwargs.pop("data", None)
            else:
                base_json = copy.deepcopy(parsed.body_json)
                mutated = apply_mutation(base_json, mutation_type, key_path, mutation_value)
                base_kwargs["json"] = mutated
                base_kwargs["_decrypted_payload"] = json.dumps(mutated)
                base_kwargs.pop("data", None)
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


def send_request(
    kwargs: dict,
    crypto_adapter: Optional[CryptoAdapter] = None,
    timeout: int = 30,
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

    return resp