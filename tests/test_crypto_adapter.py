import pytest
from src.crypto_adapter import CryptoAdapter
from src.models import CryptoProfile, Algorithm, KeyDerivation, KeyEncoding, OutputEncoding


def _make_profile(algorithm="AES-256-CBC", key_derivation="NONE", key_encoding="utf8",
                  output_encoding="base64", **kwargs):
    params = dict(
        name="test",
        algorithm=algorithm,
        key_derivation=key_derivation,
        key="test-key-32-bytes-for-aes256!!",
        key_encoding=key_encoding,
        iv="random",
        iv_encoding="utf8",
        prepend_iv_to_output=True,
        output_encoding=output_encoding,
    )
    params.update(kwargs)
    return CryptoProfile(**params)


@pytest.fixture
def passthrough():
    return CryptoAdapter()


def test_pass_through_dict(passthrough):
    data = {"hello": "world"}
    encrypted = passthrough.encrypt_payload(data)
    decrypted = passthrough.decrypt_payload(encrypted)
    assert encrypted == '{"hello": "world"}'
    assert decrypted == '{"hello": "world"}'


def test_pass_through_string(passthrough):
    data = "plain text"
    encrypted = passthrough.encrypt_payload(data)
    assert encrypted == "plain text"


def test_cbc_roundtrip():
    profile = _make_profile(algorithm="AES-256-CBC", key_derivation="NONE",
                            key="0123456789abcdef0123456789abcdef", key_encoding="hex",
                            output_encoding="base64")
    adapter = CryptoAdapter(profile)
    data = {"username": "john", "email": "john@test.com", "age": 30}
    encrypted = adapter.encrypt_payload(data)
    assert encrypted != '{"username": "john", "email": "john@test.com", "age": 30}'
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_cbc_hex_roundtrip():
    profile = _make_profile(algorithm="AES-256-CBC", key_derivation="NONE",
                            key="0123456789abcdef0123456789abcdef", key_encoding="hex",
                            output_encoding="hex")
    adapter = CryptoAdapter(profile)
    data = {"test": "value123"}
    encrypted = adapter.encrypt_payload(data)
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_gcm_roundtrip():
    profile = _make_profile(algorithm="AES-256-GCM", key_derivation="NONE",
                            key="0123456789abcdef0123456789abcdef", key_encoding="hex",
                            output_encoding="base64")
    adapter = CryptoAdapter(profile)
    data = {"secure": "data", "amount": 100}
    encrypted = adapter.encrypt_payload(data)
    assert encrypted != '{"secure": "data", "amount": 100}'
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_pbkdf2_roundtrip():
    profile = _make_profile(
        algorithm="AES-256-CBC",
        key_derivation="PBKDF2HMAC",
        key="my passphrase",
        salt="mysalt1234567890",
        iterations=1000,
    )
    adapter = CryptoAdapter(profile)
    data = {"hello": "world", "nested": {"key": "value"}}
    encrypted = adapter.encrypt_payload(data)
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_aes128_cbc_roundtrip():
    profile = _make_profile(algorithm="AES-128-CBC", key_derivation="NONE",
                            key="0123456789abcdef0123456789abcdef", key_encoding="hex",
                            output_encoding="base64")
    adapter = CryptoAdapter(profile)
    data = {"short": "key"}
    encrypted = adapter.encrypt_payload(data)
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_large_payload_roundtrip():
    profile = _make_profile(algorithm="AES-256-CBC", key_derivation="NONE",
                            key="0123456789abcdef0123456789abcdef", key_encoding="hex")
    adapter = CryptoAdapter(profile)
    data = {"data": "x" * 10000}
    encrypted = adapter.encrypt_payload(data)
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_gcm_with_pbkdf2():
    profile = CryptoProfile(
        name="test",
        algorithm=Algorithm.AES_256_GCM,
        key_derivation=KeyDerivation.PBKDF2HMAC,
        hash="SHA256",
        iterations=1000,
        key="my-passphrase",
        key_encoding=KeyEncoding.utf8,
        salt="test-salt-value",
        salt_encoding=KeyEncoding.utf8,
        iv="random",
        iv_encoding=KeyEncoding.utf8,
        prepend_iv_to_output=True,
        output_encoding=OutputEncoding.base64,
    )
    adapter = CryptoAdapter(profile)
    data = {"test": "pbkdf2+gcm"}
    encrypted = adapter.encrypt_payload(data)
    decrypted = adapter.decrypt_payload(encrypted)
    import json
    assert json.loads(decrypted) == data


def test_cryptojs_standard_checksum_layout():
    """Legacy CryptoJS layout: Salted__ + salt(8) + ciphertext, iv derived."""
    profile = CryptoProfile(
        name="test",
        algorithm=Algorithm.AES_256_CBC,
        key_derivation=KeyDerivation.EVP_BytesToKey,
        hash="MD5",
        key="cryptojs-key",
        checksum_field="checksum",
    )
    adapter = CryptoAdapter(profile)
    inner = {"a": 1, "b": "hello"}
    encrypted = adapter._encrypt_checksum(inner)
    import base64
    raw = base64.b64decode(encrypted)
    assert raw[:8] == b"Salted__"
    assert len(raw[16:]) % 16 == 0
    assert adapter._decrypt_checksum(encrypted) == inner


def test_cryptojs_iv_from_data_checksum_layout():
    """New CryptoJS layout: Salted__ + salt(8) + iv(16) + ciphertext, key-only derivation."""
    profile = CryptoProfile(
        name="test",
        algorithm=Algorithm.AES_256_CBC,
        key_derivation=KeyDerivation.EVP_BytesToKey,
        hash="MD5",
        key="cryptojs-key",
        iv_from_data=True,
        checksum_field="checksum",
    )
    adapter = CryptoAdapter(profile)
    inner = {"a": 1, "b": "hello"}
    encrypted = adapter._encrypt_checksum(inner)
    import base64
    raw = base64.b64decode(encrypted)
    assert raw[:8] == b"Salted__"
    assert len(raw) == 8 + 8 + 16 + 32  # salt + iv + one padded ciphertext block
    assert len(raw[32:]) % 16 == 0
    assert adapter._decrypt_checksum(encrypted) == inner


def test_cryptojs_iv_from_data_derives_key_matching_js():
    """Key derivation must match the JS snippet: iterative MD5, key only (32 bytes)."""
    import hashlib
    from src.crypto_adapter import CryptoAdapter

    profile = CryptoProfile(
        name="test",
        algorithm=Algorithm.AES_256_CBC,
        key_derivation=KeyDerivation.EVP_BytesToKey,
        hash="MD5",
        key="js-password",
        iv_from_data=True,
        checksum_field="checksum",
    )
    adapter = CryptoAdapter(profile)
    salt = b"12345678"
    derived = adapter._derive_evp(salt, target_len=32)

    expected = b""
    prev = b""
    while len(expected) < 32:
        prev = hashlib.md5(prev + b"js-password" + salt).digest()
        expected += prev
    expected = expected[:32]
    assert derived == expected


def _insights_profile(name="insights-payload"):
    return CryptoProfile(
        name=name,
        algorithm=Algorithm.AES_128_GCM,
        key_derivation=KeyDerivation.NONE,
        key="123#@benepik@321",
        key_encoding=KeyEncoding.utf8,
        iv="random",
        iv_length=12,
        tag_length=128,
        output_encoding=OutputEncoding.base64,
        checksum_field="data",
        gcm_nonce_field="nonce",
        gcm_tag_field="tag",
    )


def test_split_gcm_roundtrip():
    """Encrypt inner payload into split-GCM wrapper, then decrypt it back."""
    import json
    adapter = CryptoAdapter(_insights_profile())
    inner = {"token": "abc123", "hasToken": 1, "nested": {"a": 1}}
    encrypted = adapter.encrypt_body_json({}, inner)
    assert set(encrypted.keys()) == {"data", "nonce", "tag"}
    decrypted = adapter.decrypt_body_json(encrypted)
    assert decrypted == inner


def test_split_gcm_full_pipeline_roundtrip():
    """Full pipeline: decrypt wrapper, mutate inner, re-encrypt wrapper."""
    adapter = CryptoAdapter(_insights_profile())
    original = {"token": "old", "hasToken": 1}
    body = adapter.encrypt_body_json({}, original)
    inner = adapter.decrypt_body_json(body)
    assert inner == original
    inner["token"] = "mutated"
    inner["hasToken"] = 0
    wrapped = adapter.encrypt_body_json(body, inner)
    assert adapter.decrypt_body_json(wrapped) == inner


def test_split_gcm_decrypt_independent_sample():
    """Decrypt a wrapper produced by an independent AESGCM implementation
    (simulates a captured Benepik Insights response)."""
    import base64
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    expected_inner = {"token": "", "hasToken": 0}
    plaintext = json.dumps(expected_inner, separators=(",", ":")).encode("utf-8")
    key = b"123#@benepik@321"
    nonce = b"\x01" * 12
    ct_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    body = {
        "data": base64.b64encode(ct_with_tag[:-16]).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(ct_with_tag[-16:]).decode("ascii"),
    }
    adapter = CryptoAdapter(_insights_profile())
    decrypted = adapter.decrypt_body_json(body)
    assert decrypted == expected_inner


def test_split_gcm_plain_body_unchanged():
    """When gcm_nonce_field is declared but absent, the body is returned unchanged."""
    body = {"data": "not-encrypted", "foo": "bar"}
    adapter = CryptoAdapter(_insights_profile())
    assert adapter.decrypt_body_json(body) is body


def test_split_gcm_response_profile():
    """Response profile decrypts a split-GCM response body."""
    import json
    profile = _insights_profile()
    adapter = CryptoAdapter(_insights_profile("insights-payload"),
                            response_profile=_insights_profile("insights-response"))
    inner = {"token": "", "hasToken": 0}
    wrapped = adapter.encrypt_body_json({}, inner)
    assert adapter.decrypt_response_json(wrapped) == inner
