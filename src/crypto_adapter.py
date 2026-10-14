from __future__ import annotations
import hashlib
import json
import os
import base64
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.models import CryptoProfile, Algorithm, KeyDerivation, OutputEncoding

logger = logging.getLogger(__name__)

SALTED_MAGIC = b"Salted__"
JSON_SALT_SUFFIX = b"enc"


class CryptoAdapter:
    """Pluggable encrypt/decrypt driven by a CryptoProfile.

    Supports two modes:
    1. Full-body encryption: encrypts/decrypts the entire JSON body.
    2. Checksum-field mode (when profile.checksum_field is set):
       The outer JSON body wraps an encrypted inner payload in a specific field.
       The adapter decrypts that field to reveal the inner JSON for testing,
       then re-encrypts it after mutation.
    """

    def __init__(self, profile: Optional[CryptoProfile] = None,
                 response_profile: Optional[CryptoProfile] = None):
        self.profile = profile
        self.response_profile = response_profile

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt_payload(self, data: dict | str) -> str:
        if self.profile is None:
            if isinstance(data, dict):
                return json.dumps(data)
            return str(data)
        return self._encrypt(data)

    def decrypt_payload(self, ciphertext: str) -> str:
        if self.profile is None:
            return ciphertext
        return self._decrypt(ciphertext)

    def decrypt_body_json(self, body_json: dict) -> dict:
        """Decrypt request body's checksum field using the main profile."""
        return self._decrypt_body_json_for_profile(body_json, self.profile)

    def decrypt_response_json(self, body_json: dict) -> dict:
        """Decrypt response body's checksum field using response_profile if set,
        otherwise falls back to the main profile."""
        profile = self.response_profile or self.profile
        return self._decrypt_body_json_for_profile(body_json, profile)

    def _decrypt_body_json_for_profile(self, body_json: dict, profile: CryptoProfile) -> dict:
        """If checksum_field is set, decrypt that field and return the inner JSON.
        Supports both CryptoJS (Salted__) and standard (GCM/CBC) formats."""
        if profile is None or not profile.checksum_field:
            return body_json
        field = profile.checksum_field
        encrypted_val = body_json.get(field)
        if not encrypted_val or not isinstance(encrypted_val, str):
            logger.debug(f"checksum_field '{field}' not found or not a string in body")
            return body_json

        # Benepik Insights split-GCM mode: data/nonce/tag are separate top-level fields.
        # Decisive first branch — if the profile declares a nonce field and the body
        # carries it, decrypt via split-GCM; if declared but absent, body is plain.
        if profile.gcm_nonce_field:
            nonce_val = body_json.get(profile.gcm_nonce_field)
            tag_val = body_json.get(profile.gcm_tag_field) if profile.gcm_tag_field else None
            if not nonce_val or not isinstance(nonce_val, str) or not isinstance(tag_val, str):
                logger.debug(
                    f"split-GCM fields '{profile.gcm_nonce_field}'/'{profile.gcm_tag_field}' "
                    f"not found in body, treating as plain"
                )
                return body_json
            saved_profile = self.profile
            self.profile = profile
            try:
                inner = self._decrypt_split_gcm(encrypted_val, nonce_val, tag_val)
                logger.info(f"Decrypted split-GCM fields -> {len(inner)} inner keys")
                self._checksum_format = "split-gcm"
                return inner
            except Exception as e:
                logger.warning(
                    f"split-GCM decryption failed for fields '{field}'/'{profile.gcm_nonce_field}': {e}"
                )
                return body_json
            finally:
                self.profile = saved_profile

        # Temporarily swap to the given profile for internal methods
        saved_profile = self.profile
        self.profile = profile
        try:
            # Try JSON-wrapped format first (Java JWE style, base64-encoded JSON envelope)
            if profile.json_format:
                try:
                    inner = self._decrypt_json_format(encrypted_val)
                    logger.info(f"Decrypted checksum field '{field}' (json_format) -> {len(inner)} inner keys")
                    self._checksum_format = "json_format"
                    return inner
                except Exception as e:
                    logger.debug(f"JSON format decrypt failed: {e}")

            # Try CryptoJS format with the profile's own key first
            try:
                inner = self._decrypt_checksum(encrypted_val)
                logger.info(f"Decrypted checksum field '{field}' (CryptoJS) -> {len(inner)} inner keys")
                self._checksum_format = "cryptojs"
                return inner
            except Exception as e:
                logger.debug(f"CryptoJS decrypt with profile key failed: {e}")
                pass

            # Try fallback CryptoJS keys (configured via profile.fallback_keys)
            # When a fallback key succeeds, set format to "standard" so re-encryption
            # uses the profile's own encryption (GCM/CBC) rather than CryptoJS.
            for fallback_key in profile.fallback_keys:
                if fallback_key == profile.key:
                    continue
                try:
                    inner = self._decrypt_checksum(encrypted_val, password_override=fallback_key)
                    logger.info(f"Decrypted checksum field '{field}' (CryptoJS fallback key) -> {len(inner)} inner keys")
                    self._checksum_format = "standard"
                    return inner
                except Exception as e:
                    logger.debug(f"Fallback CryptoJS key '{fallback_key}' failed: {e}")
                    pass

            # Fall back to standard decrypt (GCM, CBC, etc.)
            # Skip if key_derivation is EVP_BytesToKey — only CryptoJS format applies
            if profile.key_derivation != KeyDerivation.EVP_BytesToKey:
                try:
                    decrypted_str = self._decrypt(encrypted_val)
                    inner = json.loads(decrypted_str)
                    logger.info(f"Decrypted checksum field '{field}' (standard) -> {len(inner)} inner keys")
                    self._checksum_format = "standard"
                    return inner
                except Exception as e:
                    logger.debug(f"Failed to decrypt checksum field '{field}' via standard decrypt: {e}")
                    # Try with salt_from_data=True as fallback (embedded 16-byte salt)
                    if not profile.salt_from_data:
                        saved_sfd = profile.salt_from_data
                        profile.salt_from_data = True
                        try:
                            decrypted_str = self._decrypt(encrypted_val)
                            inner = json.loads(decrypted_str)
                            logger.info(f"Decrypted checksum field '{field}' (salt_from_data fallback) -> {len(inner)} inner keys")
                            self._checksum_format = "standard"
                            return inner
                        except Exception as e2:
                            logger.debug(f"salt_from_data fallback also failed: {e2}")
                        finally:
                            profile.salt_from_data = saved_sfd
                    logger.warning(
                        f"Checksum decryption failed for field '{field}' — "
                        f"profile key and all fallback keys failed. "
                        f"Checksum starts with: {encrypted_val[:20]!r}... "
                        f"Profile: {profile.name} (algo={profile.algorithm}, kdf={profile.key_derivation})"
                    )
                    return body_json

            logger.debug(f"Failed to decrypt checksum field '{field}' — CryptoJS decryption failed (wrong key?)")
            logger.warning(
                f"Checksum decryption failed for field '{field}' — "
                f"no fallback key could decrypt (EVP_BytesToKey profile). "
                f"Checksum starts with: {encrypted_val[:20]!r}..."
            )
            return body_json
        finally:
            self.profile = saved_profile

    def encrypt_body_json(self, body_json: dict, inner_json: dict) -> dict:
        """If checksum_field is set, encrypt inner_json and place it in the field.
        Uses the same format (CryptoJS or standard) that was used for decryption."""
        if self.profile is None or not self.profile.checksum_field:
            return inner_json
        field = self.profile.checksum_field

        fmt = getattr(self, '_checksum_format', None)
        if fmt == 'split-gcm' or (fmt is None and self.profile.gcm_nonce_field):
            result = dict(body_json)
            result.update(self._encrypt_split_gcm(inner_json))
            return result

        if fmt == 'cryptojs':
            encrypted = self._encrypt_checksum(inner_json)
        elif fmt == 'json_format' or (fmt is None and self.profile.json_format):
            encrypted = self._encrypt_json_format(inner_json)
        else:
            encrypted = self._encrypt(inner_json)

        result = dict(body_json)
        result[field] = encrypted
        return result

    def has_checksum_mode(self) -> bool:
        return self.profile is not None and bool(self.profile.checksum_field)

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def _derive_key(self, salt_override: Optional[bytes] = None) -> bytes:
        profile = self.profile
        if profile.key_derivation == KeyDerivation.EVP_BytesToKey:
            raise ValueError(
                "EVP_BytesToKey requires checksum_field to be set. "
                "Use checksum_field mode or a different key_derivation."
            )
        key_bytes = self._decode_key_material(profile.key, profile.key_encoding)

        if profile.key_derivation == KeyDerivation.NONE:
            return key_bytes

        salt = salt_override if salt_override is not None else self._get_salt()
        hash_algo = getattr(hashes, profile.hash.value)()
        kdf = PBKDF2HMAC(
            algorithm=hash_algo,
            length=self._key_length(),
            salt=salt,
            iterations=profile.iterations,
        )
        return kdf.derive(key_bytes)

    def _derive_evp(self, salt: bytes, password_override: Optional[str] = None,
                    target_len: int = 48):
        """OpenSSL EVP_BytesToKey with MD5 (CryptoJS-compatible).

        Derives key+iv from password + salt using iterative MD5.
        For AES-256-CBC: needs 32 key bytes + 16 iv bytes = 48 total.
        When iv_from_data is set, only the key is derived (target_len=32)
        and the IV is read from the payload.
        """
        pw = password_override if password_override is not None else self.profile.key
        password = pw.encode("utf-8")
        digest = b""
        prev = b""
        while len(digest) < target_len:
            prev = hashlib.md5(prev + password + salt).digest()
            digest += prev
        return digest[:target_len]

    def _get_salt(self) -> bytes:
        profile = self.profile
        if profile.salt:
            return self._decode_key_material(profile.salt, profile.salt_encoding)
        key_bytes = self._decode_key_material(profile.key, profile.key_encoding)
        return key_bytes[:16]

    def _decode_key_material(self, value: str, encoding: str) -> bytes:
        if encoding == "hex":
            return bytes.fromhex(value)
        elif encoding == "base64":
            val = value.strip()
            missing = (4 - len(val) % 4) % 4
            if missing:
                val += "=" * missing
            return base64.b64decode(val)
        elif encoding == "base64url":
            val = value.strip().replace("-", "+").replace("_", "/")
            missing = (4 - len(val) % 4) % 4
            if missing:
                val += "=" * missing
            return base64.b64decode(val)
        else:
            return value.encode("utf-8")

    def _key_length(self) -> int:
        algo = self.profile.algorithm
        if algo in (Algorithm.AES_256_CBC, Algorithm.AES_256_GCM):
            return 32
        elif algo in (Algorithm.AES_128_CBC, Algorithm.AES_128_GCM):
            return 16
        return 32

    def _iv_length(self) -> int:
        return self.profile.iv_length

    def _get_iv(self) -> bytes:
        profile = self.profile
        if profile.iv == "random":
            return os.urandom(self._iv_length())
        return self._decode_key_material(profile.iv, profile.iv_encoding)

    # ------------------------------------------------------------------
    # CryptoJS checksum-field encrypt / decrypt
    # ------------------------------------------------------------------

    def _encrypt_checksum(self, data: dict) -> str:
        """Encrypt inner payload in CryptoJS-compatible format.

        Standard format: base64('Salted__' + 8-byte-salt + AES-256-CBC-ciphertext)
        iv_from_data format: base64('Salted__' + 8-byte-salt + 16-byte-iv + ciphertext)
        """
        plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
        salt = os.urandom(8)

        if self.profile.iv_from_data:
            key = self._derive_evp(salt, target_len=32)
            iv = os.urandom(16)
        else:
            derived = self._derive_evp(salt)
            key, iv = derived[:32], derived[32:48]

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        if self.profile.iv_from_data:
            output = SALTED_MAGIC + salt + iv + ciphertext
        else:
            output = SALTED_MAGIC + salt + ciphertext
        return base64.b64encode(output).decode("ascii")

    def _decrypt_checksum(self, encrypted: str, password_override: Optional[str] = None) -> dict:
        """Decrypt a CryptoJS-format checksum value to a JSON dict."""
        raw = base64.b64decode(encrypted)
        if raw[:8] != SALTED_MAGIC:
            raise ValueError("Not a valid CryptoJS encrypted payload (missing Salted__)")
        salt = raw[8:16]

        if self.profile.iv_from_data:
            iv = raw[16:32]
            ciphertext = raw[32:]
            key = self._derive_evp(salt, password_override, target_len=32)
        else:
            ciphertext = raw[16:]
            derived = self._derive_evp(salt, password_override)
            key, iv = derived[:32], derived[32:48]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        return json.loads(plaintext.decode("utf-8"))

    # ------------------------------------------------------------------
    # Split-GCM checksum-field encrypt / decrypt (Benepik Insights)
    # ------------------------------------------------------------------

    def _decrypt_split_gcm(self, data_b64: str, nonce_b64: str, tag_b64: str) -> dict:
        """Decrypt a split-GCM payload where data/nonce/tag are separate
        base64-encoded fields and the key is used raw (no KDF)."""
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(data_b64)
        key = self._derive_key()
        aad = self.profile.aad.encode("utf-8") if self.profile.aad else b""
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(plaintext.decode("utf-8"))

    def _encrypt_split_gcm(self, inner_json: dict) -> dict:
        """Encrypt inner payload into split-GCM wrapper fields
        ({checksum_field}/{gcm_nonce_field}/{gcm_tag_field}), base64-encoded."""
        profile = self.profile
        plaintext = json.dumps(inner_json, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        key = self._derive_key()
        aad = profile.aad.encode("utf-8") if profile.aad else b""
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return {
            profile.checksum_field: base64.b64encode(ciphertext).decode("ascii"),
            profile.gcm_nonce_field: base64.b64encode(nonce).decode("ascii"),
            profile.gcm_tag_field: base64.b64encode(tag).decode("ascii"),
        }

    # ------------------------------------------------------------------
    # JSON-wrapped encrypt / decrypt (Java JWE style)
    # ------------------------------------------------------------------

    def _decrypt_json_format(self, encrypted: str) -> dict:
        """Decrypt a JSON-wrapped payload where the checksum field contains
        a base64-encoded JSON object with named fields (salt, iv, ciphertext, tag)
        in hex/base64 encoding. The PBKDF2 salt is the envelope salt bytes with
        the ASCII suffix "enc" appended (matches the PHP/JS reference
        implementation)."""
        profile = self.profile
        raw_json = base64.b64decode(encrypted)
        envelope = json.loads(raw_json.decode("utf-8"))

        salt = bytes.fromhex(envelope["salt"])
        iv = bytes.fromhex(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        tag = bytes.fromhex(envelope["tag"])

        key_bytes = self._decode_key_material(profile.key, profile.key_encoding)
        hash_algo = getattr(hashes, profile.hash.value)()
        kdf = PBKDF2HMAC(
            algorithm=hash_algo,
            length=self._key_length(),
            salt=salt + JSON_SALT_SUFFIX,
            iterations=profile.iterations,
        )
        key = kdf.derive(key_bytes)

        aad = profile.aad.encode("utf-8") if profile.aad else b""
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
        return json.loads(plaintext.decode("utf-8"))

    def _encrypt_json_format(self, inner_json: dict) -> str:
        """Encrypt inner payload into JSON-wrapped format (Java JWE style).
        Returns a base64-encoded JSON object with named fields. The envelope
        salt is 32 random bytes stored in hex; the PBKDF2 salt appends the
        ASCII suffix "enc" to those bytes (matches the PHP/JS reference
        implementation)."""
        profile = self.profile
        plaintext = json.dumps(inner_json, separators=(",", ":")).encode("utf-8")

        salt = os.urandom(32)
        iv = os.urandom(profile.iv_length)

        key_bytes = self._decode_key_material(profile.key, profile.key_encoding)
        hash_algo = getattr(hashes, profile.hash.value)()
        kdf = PBKDF2HMAC(
            algorithm=hash_algo,
            length=self._key_length(),
            salt=salt + JSON_SALT_SUFFIX,
            iterations=profile.iterations,
        )
        key = kdf.derive(key_bytes)

        aad = profile.aad.encode("utf-8") if profile.aad else b""
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        envelope = {
            "v": 3,
            "cipher": profile.algorithm.value.lower(),
            "salt": salt.hex(),
            "iv": iv.hex(),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": tag.hex(),
        }
        return base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")

    # ------------------------------------------------------------------
    # Full-body encrypt / decrypt (original mode)
    # ------------------------------------------------------------------

    def _encrypt(self, data: dict | str) -> str:
        profile = self.profile
        if isinstance(data, dict):
            plaintext = json.dumps(data).encode("utf-8")
        else:
            plaintext = str(data).encode("utf-8")

        if profile.salt_from_data:
            salt = os.urandom(16)
            key = self._derive_key(salt_override=salt)
        else:
            key = self._derive_key()
            salt = None
        iv = self._get_iv()
        algo = profile.algorithm

        if algo in (Algorithm.AES_256_GCM, Algorithm.AES_128_GCM):
            aad = profile.aad.encode("utf-8") if profile.aad else b""
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
            encryptor.authenticate_additional_data(aad)
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            body = iv + ciphertext + tag
            if salt is not None:
                body = salt + body
            output = body
        else:
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            if salt is not None:
                # Salt is random per-encryption, so the IV must be stored with it
                output = salt + iv + ciphertext
            elif profile.prepend_iv_to_output:
                output = iv + ciphertext
            else:
                output = ciphertext

        return self._encode_output(output)

    def _decrypt(self, ciphertext: str) -> str:
        profile = self.profile
        raw = self._decode_key_material(ciphertext, profile.output_encoding.value)
        algo = profile.algorithm

        if algo in (Algorithm.AES_256_GCM, Algorithm.AES_128_GCM):
            aad = profile.aad.encode("utf-8") if profile.aad else b""
            if profile.salt_from_data:
                salt_len = 16
                salt = raw[:salt_len]
                iv = raw[salt_len:salt_len + profile.iv_length]
                ct_with_tag = raw[salt_len + profile.iv_length:]
                key = self._derive_key(salt_override=salt)
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(iv, ct_with_tag, aad)
            else:
                key = self._derive_key()
                iv_len = profile.iv_length
                tag_len = profile.tag_length // 8
                iv = raw[:iv_len]
                tag = raw[-tag_len:]
                ct = raw[iv_len:-tag_len]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()
                decryptor.authenticate_additional_data(aad)
                plaintext = decryptor.update(ct) + decryptor.finalize()
        else:
            if profile.salt_from_data:
                # Layout: salt(16) + iv + ciphertext
                salt = raw[:16]
                key = self._derive_key(salt_override=salt)
                rest = raw[16:]
                iv = rest[:profile.iv_length]
                ct = rest[profile.iv_length:]
            else:
                key = self._derive_key()
                if profile.prepend_iv_to_output:
                    iv_len = profile.iv_length
                    iv = raw[:iv_len]
                    ct = raw[iv_len:]
                else:
                    iv = self._get_iv()
                    ct = raw
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()

        return plaintext.decode("utf-8")

    def _encode_output(self, data: bytes) -> str:
        if self.profile.output_encoding == OutputEncoding.hex:
            return data.hex()
        encoded = base64.b64encode(data).decode("ascii")
        if self.profile.output_encoding == OutputEncoding.base64url:
            return encoded.replace("+", "-").replace("/", "_").rstrip("=")
        return encoded
