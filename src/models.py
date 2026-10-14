from __future__ import annotations
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, model_validator
from enum import Enum


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParsedRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body_raw: str = ""
    body_json: Optional[Dict[str, Any]] = None
    cookies: Dict[str, str] = Field(default_factory=dict)
    insecure: bool = False


class KeyDerivation(str, Enum):
    PBKDF2HMAC = "PBKDF2HMAC"
    NONE = "NONE"
    EVP_BytesToKey = "EVP_BytesToKey"


class HashAlgo(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    MD5 = "MD5"


class KeyEncoding(str, Enum):
    utf8 = "utf8"
    base64 = "base64"
    hex = "hex"


class OutputEncoding(str, Enum):
    base64 = "base64"
    base64url = "base64url"
    hex = "hex"


class Algorithm(str, Enum):
    AES_256_CBC = "AES-256-CBC"
    AES_256_GCM = "AES-256-GCM"
    AES_128_CBC = "AES-128-CBC"
    AES_128_GCM = "AES-128-GCM"


class CryptoProfile(BaseModel):
    name: str = "default"
    algorithm: Algorithm = Algorithm.AES_256_CBC
    key_derivation: KeyDerivation = KeyDerivation.PBKDF2HMAC
    hash: HashAlgo = HashAlgo.SHA256
    iterations: int = 10000
    key: str
    key_encoding: KeyEncoding = KeyEncoding.utf8
    salt: Optional[str] = None
    salt_encoding: KeyEncoding = KeyEncoding.utf8
    iv: str = "random"
    iv_length: int = 16
    iv_encoding: KeyEncoding = KeyEncoding.utf8
    prepend_iv_to_output: bool = True
    tag_length: int = 128
    aad: Optional[str] = None
    output_encoding: OutputEncoding = OutputEncoding.base64
    salt_from_data: bool = False
    iv_from_data: bool = False
    checksum_field: Optional[str] = None
    gcm_nonce_field: Optional[str] = None
    gcm_tag_field: Optional[str] = None
    fallback_keys: List[str] = Field(default_factory=list)
    json_format: bool = False

    @field_validator("iterations")
    @classmethod
    def iterations_must_be_positive(cls, v):
        if v < 1:
            raise ValueError("iterations must be >= 1")
        return v

    @field_validator("key")
    @classmethod
    def key_not_empty(cls, v):
        if not v:
            raise ValueError("key must not be empty")
        return v

    @model_validator(mode="after")
    def validate_iv_usage(self):
        gcm = self.algorithm in (Algorithm.AES_256_GCM, Algorithm.AES_128_GCM)
        if gcm:
            if self.iv != "random":
                raise ValueError(
                    f"GCM profile '{self.name}' must use 'iv: random'; "
                    "a fixed IV/nonce would be reused across requests, "
                    "which is insecure and produces identical ciphertexts"
                )
            if self.iv_length not in (8, 12, 16):
                raise ValueError(
                    f"GCM profile '{self.name}' requires iv_length of 8, 12 or 16 "
                    f"(NIST-allowed nonce sizes), got {self.iv_length}"
                )
        elif self.iv == "random" and not self.prepend_iv_to_output:
            raise ValueError(
                f"CBC profile '{self.name}' cannot combine 'iv: random' with "
                "'prepend_iv_to_output: false' — the IV would not be stored "
                "and could never be recovered at decryption time"
            )
        if self.gcm_nonce_field and not self.checksum_field:
            raise ValueError(
                f"Profile '{self.name}' sets gcm_nonce_field but no checksum_field"
            )
        return self


class TestCaseScope(str, Enum):
    HEADER = "Header"
    PAYLOAD_KEY = "PayloadKey"
    GLOBAL = "Global"


class TestCaseType(str, Enum):
    VALIDATION = "Validation"
    VULNERABILITY = "Vulnerability"
    AUTH = "Auth"
    BOUNDARY = "Boundary"
    NEGATIVE = "Negative"


class MutationType(str, Enum):
    REMOVE_KEY = "remove_key"
    EMPTY_VALUE = "empty_value"
    NULL_VALUE = "null_value"
    ALPHA_ONLY = "alpha_only"
    NUMERIC_ONLY = "numeric_only"
    SPECIAL_CHARS = "special_chars"
    MAX_LENGTH_EXCEED = "max_length_exceed"
    MIN_LENGTH_VIOLATE = "min_length_violate"
    SQL_INJECTION = "sql_injection"
    XSS_PAYLOAD = "xss_payload"
    OVERSIZED_PAYLOAD = "oversized_payload"
    UNICODE_EMOJI = "unicode_emoji"
    WRONG_TYPE = "wrong_type"
    MALFORMED_JSON = "malformed_json"
    HEADER_MISSING = "header_missing"
    HEADER_INVALID_VALUE = "header_invalid_value"
    AUTH_TOKEN_MISSING = "auth_token_missing"
    AUTH_TOKEN_INVALID = "auth_token_invalid"
    AUTH_TOKEN_EXPIRED = "auth_token_expired"
    BASELINE = "baseline"
    QUERY_PARAM_INVALID = "query_param_invalid"
    QUERY_PARAM_INJECT = "query_param_inject"
    METHOD_CHANGE = "method_change"
    INJECT_EXTRA_KEY = "inject_extra_key"
    NOSQL_INJECTION = "nosql_injection"
    SECURITY_HEADERS_CHECK = "security_headers_check"
    CORS_CHECK = "cors_check"
    SENSITIVE_DATA_SCAN = "sensitive_data_scan"
    ERROR_LEAK_SCAN = "error_leak_scan"
    SCHEMA_VALIDATION = "schema_validation"
    PERFORMANCE_CHECK = "performance_check"
    DUPLICATE_SUBMIT = "duplicate_submit"


class TestCase(BaseModel):
    test_case_id: str
    scope: TestCaseScope
    test_case_type: TestCaseType
    description: str
    mutation_type: MutationType
    mutation_value: Optional[str] = None
    expected_status_code_range: Optional[str] = None
    expected_behavior: str = ""
    applies_to_mandatory_only: bool = True
    enabled: bool = True


class TestResult(BaseModel):
    api: str
    key: str
    test_case: str
    test_case_id: str = ""
    test_case_type: str
    status: str
    mandatory: str
    status_code: int
    response: str = ""
    decrypted_response: str = ""
    decrypted_payload: str = ""
    encrypted_payload: str = ""


class Settings(BaseModel):
    request_delay_ms: int = 200
    timeout_seconds: int = 30
    max_retries: int = 3
    validation_error_keywords: List[str] = Field(
        default_factory=lambda: ["required", "missing", "mandatory"]
    )
    max_nesting_depth: int = 3
    include_non_mandatory: bool = False
    skip_baseline: bool = False


class MandatoryResult(BaseModel):
    is_mandatory: bool
    evidence_status_code: int
    evidence_response_snippet: str
