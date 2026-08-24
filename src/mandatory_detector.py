from __future__ import annotations
import copy
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from src.models import ParsedRequest, MandatoryResult, Settings
from src.curl_parser import curl_to_requests_kwargs
from src.crypto_adapter import CryptoAdapter

logger = logging.getLogger(__name__)


def _get_all_keys(data: Any, prefix: str = "", max_depth: int = 3, depth: int = 0) -> List[str]:
    """Recursively get all dot-path keys from a nested dict up to max_depth."""
    keys: List[str] = []
    if depth > max_depth:
        return keys
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append(full_key)
            if isinstance(v, dict) and depth < max_depth:
                keys.extend(_get_all_keys(v, full_key, max_depth, depth + 1))
    return keys


def _is_validation_error(text: str, keywords: List[str]) -> bool:
    lower = text.lower()
    for kw in keywords:
        if kw.lower() in lower:
            return True
    return False


def detect_mandatory_fields(
    parsed: ParsedRequest,
    settings: Optional[Settings] = None,
    crypto_adapter: Optional[CryptoAdapter] = None,
    cancel_event: Optional[threading.Event] = None,
    rate_guard=None,
    pause_controller=None,
) -> Dict[str, MandatoryResult]:
    """Detect which payload keys are mandatory by removing each and checking the response.

    When crypto_adapter.has_checksum_mode() is True, the outer body wraps an
    encrypted inner payload.  This function decrypts the inner payload, finds
    keys there, and sends mutated inner payloads re-encrypted in the wrapper.

    When a pause_controller is supplied, the loop pauses before each key check
    and restarts from scratch with the new payload if it changed while paused.
    """
    if settings is None:
        settings = Settings()
    if crypto_adapter is None:
        crypto_adapter = CryptoAdapter()

    def _prepare():
        """Derive the inner payload, request kwargs and baseline for the
        current parsed request. Returns (inner_json, kwargs, baseline_status,
        all_keys); inner_json is None when detection is not possible."""
        checksum_mode = crypto_adapter.has_checksum_mode()
        full_body_mode = (
            not checksum_mode
            and crypto_adapter.profile is not None
            and parsed.body_json is None
            and bool(parsed.body_raw)
        )

        if parsed.body_json is None and not full_body_mode:
            logger.info("No JSON body - skipping mandatory detection")
            return None, None, 0, []

        if checksum_mode:
            # Check if body actually has a checksum field before attempting decrypt
            checksum_field = crypto_adapter.profile.checksum_field
            if parsed.body_json and checksum_field in parsed.body_json:
                inner_json = crypto_adapter.decrypt_body_json(parsed.body_json)
                if inner_json is parsed.body_json:
                    logger.warning("Checksum decryption returned unchanged body — cannot detect inner keys")
                    return None, None, 0, []
                logger.info(f"Using inner payload with keys: {list(inner_json.keys())}")
            else:
                logger.info(f"No '{checksum_field}' field in body — using plain JSON body")
                inner_json = parsed.body_json
        elif full_body_mode:
            # Full-body encryption: body is raw encrypted string
            try:
                inner_str = crypto_adapter.decrypt_payload(parsed.body_raw)
                inner_json = json.loads(inner_str)
                logger.info(f"Using full-body encrypted payload with keys: {list(inner_json.keys())}")
            except Exception as e:
                logger.warning(f"Full-body decryption failed: {e}")
                return None, None, 0, []
        else:
            inner_json = parsed.body_json

        kwargs = curl_to_requests_kwargs(parsed)

        # Send baseline request (original curl, unchanged)
        try:
            baseline_resp = _send_request(kwargs, parsed, crypto_adapter, settings, rate_guard=rate_guard)
            baseline_status = baseline_resp.status_code
        except requests.RequestException as e:
            logger.warning(f"Baseline request failed: {e} — skipping mandatory detection")
            return None, None, 0, []
        logger.info(f"Baseline: {baseline_status}")

        # Get all keys from the INNER payload
        all_keys = _get_all_keys(inner_json, max_depth=settings.max_nesting_depth)
        logger.info(f"Found {len(all_keys)} keys to check for mandatory status")
        return inner_json, kwargs, baseline_status, all_keys

    inner_json, kwargs, baseline_status, all_keys = _prepare()
    if inner_json is None:
        return {}

    results: Dict[str, MandatoryResult] = {}
    current_parsed = parsed
    i = 0

    while i < len(all_keys):
        if pause_controller is not None:
            pause_controller.wait_if_paused(cancel_event)
            if pause_controller.parsed is not None:
                parsed = pause_controller.parsed
            if pause_controller.settings is not None:
                settings = pause_controller.settings
            if pause_controller.adapter is not None:
                crypto_adapter = pause_controller.adapter
            rate_guard.settings = settings
            if parsed is not current_parsed:
                logger.info("Payload changed while paused — restarting mandatory detection with the new payload")
                results = {}
                current_parsed = parsed
                inner_json, kwargs, baseline_status, all_keys = _prepare()
                if inner_json is None:
                    return results
                i = 0
                continue

        if cancel_event and cancel_event.is_set():
            logger.info("Mandatory detection cancelled")
            break

        key_path = all_keys[i]
        # Remove key from the inner payload
        mutated_inner = copy.deepcopy(inner_json)
        parts = key_path.split(".")
        current = mutated_inner
        for part in parts[:-1]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                break
        else:
            if isinstance(current, dict) and parts[-1] in current:
                del current[parts[-1]]

        # Build the request body: re-encrypt inner or use plain
        checksum_mode = crypto_adapter.has_checksum_mode()
        if checksum_mode:
            mutated_body = crypto_adapter.encrypt_body_json(parsed.body_json, mutated_inner)
            test_kwargs = dict(kwargs)
            test_kwargs["json"] = mutated_body
            skip_encrypt = True
        elif crypto_adapter.profile is not None and parsed.body_json is None and bool(parsed.body_raw):
            re_encrypted = crypto_adapter.encrypt_payload(mutated_inner)
            test_kwargs = dict(kwargs)
            test_kwargs["data"] = re_encrypted
            test_kwargs.pop("json", None)
            skip_encrypt = True
        else:
            test_kwargs = dict(kwargs)
            test_kwargs["json"] = mutated_inner
            skip_encrypt = False

        try:
            resp = _send_request_with_kwargs(test_kwargs, crypto_adapter, settings,
                                             skip_encrypt=skip_encrypt, rate_guard=rate_guard)
            snippet = resp.text[:300]
            is_error = False

            if baseline_status < 400 and resp.status_code >= 400:
                is_error = True
            elif _is_validation_error(snippet, settings.validation_error_keywords):
                is_error = True

            result = MandatoryResult(
                is_mandatory=is_error,
                evidence_status_code=resp.status_code,
                evidence_response_snippet=snippet[:200],
            )
            results[key_path] = result
            logger.info(f"  mandatory={is_error} | key={key_path} | HTTP {resp.status_code}")

            time.sleep(settings.request_delay_ms / 1000.0)
        except Exception as e:
            logger.warning(f"Error checking key '{key_path}': {e}")
            results[key_path] = MandatoryResult(
                is_mandatory=False,
                evidence_status_code=0,
                evidence_response_snippet=str(e),
            )
        i += 1

    return results


def _send_request(
    kwargs: dict,
    parsed: ParsedRequest,
    crypto_adapter: CryptoAdapter,
    settings: Settings,
    rate_guard=None,
) -> requests.Response:
    skip = crypto_adapter.has_checksum_mode()
    if not skip and crypto_adapter.profile is not None:
        # Full-body encryption mode: body is already encrypted
        skip = (not crypto_adapter.profile.checksum_field
                and crypto_adapter.profile.salt_from_data)
    return _send_request_with_kwargs(kwargs, crypto_adapter, settings,
                                     skip_encrypt=skip, rate_guard=rate_guard)


def _send_request_with_kwargs(
    kwargs: dict,
    crypto_adapter: CryptoAdapter,
    settings: Settings,
    skip_encrypt: bool = False,
    rate_guard=None,
) -> requests.Response:
    """Send request, applying crypto adapter to JSON body if present.

    Args:
        skip_encrypt: When True, skip full-body encryption (used in checksum_field mode
                      where the body is already wrapped with the encrypted inner payload).
    """
    kwargs = dict(kwargs)

    # Encrypt body if crypto is active and not skipped
    if not skip_encrypt and "json" in kwargs and crypto_adapter.profile is not None:
        encrypted = crypto_adapter.encrypt_payload(kwargs["json"])
        kwargs.pop("json", None)
        kwargs["data"] = encrypted
        headers = dict(kwargs.get("headers", {}))
        headers["Content-Type"] = "application/jose"
        kwargs["headers"] = headers

    method = kwargs.pop("method", "POST")
    url = kwargs.pop("url")
    for attempt in range(settings.max_retries):
        try:
            resp = requests.request(
                method=method,
                url=url,
                timeout=settings.timeout_seconds,
                **kwargs,
            )

            # Decrypt response only if it looks like encrypted data
            if crypto_adapter.profile is not None:
                ct = resp.headers.get("Content-Type", "")
                is_encrypted_ct = "jose" in ct.lower()
                # For full-body encryption, also check text/plain responses
                if not is_encrypted_ct and not crypto_adapter.has_checksum_mode():
                    is_encrypted_ct = crypto_adapter.profile.salt_from_data
                if is_encrypted_ct:
                    try:
                        decrypted_body = crypto_adapter.decrypt_payload(resp.text)
                        resp._crypto_decrypted = decrypted_body
                    except Exception:
                        pass
                elif not crypto_adapter.has_checksum_mode():
                    # Full-body mode: server may serve encrypted data as application/json
                    try:
                        decrypted_body = crypto_adapter.decrypt_payload(resp.text)
                        json.loads(decrypted_body)
                        resp._crypto_decrypted = decrypted_body
                    except Exception:
                        pass
                # Also try checksum-field decryption on response body
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
        except requests.RequestException as e:
            if attempt < settings.max_retries - 1:
                logger.warning(f"Request failed (attempt {attempt+1}): {e}, retrying...")
                time.sleep(1)
            else:
                raise