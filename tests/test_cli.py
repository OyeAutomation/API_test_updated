import pytest

from src.cli import _load_crypto_profile, build_settings
from src.models import Settings


def test_load_crypto_profile_found(tmp_path):
    f = tmp_path / "profiles.yaml"
    f.write_text(
        "profiles:\n"
        "  - name: default\n"
        "    algorithm: AES-256-CBC\n"
        "    key: secret\n"
        "  - name: other\n"
        "    algorithm: AES-128-GCM\n"
        "    key: other-key\n"
    )
    profile = _load_crypto_profile(str(f), "other")
    assert profile["algorithm"] == "AES-128-GCM"


def test_load_crypto_profile_missing_name_raises(tmp_path):
    f = tmp_path / "profiles.yaml"
    f.write_text("profiles:\n  - name: default\n    key: secret\n")
    with pytest.raises(ValueError, match="not found"):
        _load_crypto_profile(str(f), "typo")


def test_load_crypto_profile_none_path_returns_none():
    assert _load_crypto_profile(None, "default") is None


def test_build_settings_loads_yaml_and_cli_wins(tmp_path):
    f = tmp_path / "settings.yaml"
    f.write_text(
        "request_delay_ms: 999\n"
        "timeout_seconds: 999\n"
        "max_retries: 7\n"
        "validation_error_keywords:\n"
        "  - error\n"
        "  - invalid\n"
        "max_nesting_depth: 5\n"
        "include_non_mandatory: true\n"
    )
    s = build_settings(str(f), delay=50, timeout=10, include_non_mandatory=False)
    assert isinstance(s, Settings)
    assert s.request_delay_ms == 50       # CLI wins
    assert s.timeout_seconds == 10        # CLI wins
    assert s.max_retries == 7             # from file
    assert s.max_nesting_depth == 5       # from file
    assert "error" in s.validation_error_keywords
    assert s.include_non_mandatory is False  # CLI wins


def test_build_settings_no_file_uses_defaults():
    s = build_settings(None, delay=50, timeout=10, include_non_mandatory=True)
    assert s.request_delay_ms == 50
    assert s.timeout_seconds == 10
    assert s.max_retries == 3
    assert s.include_non_mandatory is True


def test_build_settings_invalid_yaml_raises(tmp_path):
    f = tmp_path / "settings.yaml"
    f.write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="mapping"):
        build_settings(str(f), delay=1, timeout=1, include_non_mandatory=False)