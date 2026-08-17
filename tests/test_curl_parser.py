import pytest
from src.curl_parser import parse_curl
from src.models import HttpMethod


def test_simple_get():
    curl = "curl https://api.example.com/users"
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.GET
    assert parsed.url == "https://api.example.com/users"


def test_post_with_json():
    curl = """curl -X POST https://api.example.com/users \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer token123" \\
    -d '{"username":"john","email":"john@test.com"}'"""
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.POST
    assert parsed.url == "https://api.example.com/users"
    assert parsed.headers["Content-Type"] == "application/json"
    assert parsed.headers["Authorization"] == "Bearer token123"
    assert parsed.body_json == {"username": "john", "email": "john@test.com"}


def test_query_params():
    curl = "curl 'https://api.example.com/search?q=hello&page=1'"
    parsed = parse_curl(curl)
    assert parsed.url == "https://api.example.com/search"
    assert parsed.query_params == {"q": "hello", "page": "1"}


def test_custom_method():
    curl = "curl -X DELETE https://api.example.com/users/123"
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.DELETE


def test_basic_auth():
    curl = "curl -u admin:secret https://api.example.com/protected"
    parsed = parse_curl(curl)
    assert "Authorization" in parsed.headers
    assert parsed.headers["Authorization"].startswith("Basic ")


def test_cookies():
    curl = """curl -b "session_id=abc123; theme=dark" https://api.example.com/dashboard"""
    parsed = parse_curl(curl)
    assert parsed.cookies.get("session_id") == "abc123"
    assert parsed.cookies.get("theme") == "dark"


def test_data_raw():
    curl = """curl -X POST https://api.example.com/data \\
    --data-raw '{"key":"value"}'"""
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.POST
    assert parsed.body_json == {"key": "value"}


def test_multiline_with_backslash():
    curl = """curl -X PUT \\
    https://api.example.com/users/1 \\
    -H "Content-Type: application/json" \\
    -d '{"name":"Updated"}'"""
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.PUT
    assert parsed.body_json == {"name": "Updated"}


def test_ignore_compressed():
    curl = "curl --compressed https://api.example.com/data"
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.GET


def test_put_with_body_no_content_type():
    curl = """curl -X PUT https://api.example.com/items/1 -d '{"name":"test"}'"""
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.PUT
    assert parsed.body_json == {"name": "test"}
    # Should auto-detect JSON
    assert "Content-Type" in parsed.headers


def test_empty_body():
    curl = "curl -X POST https://api.example.com/empty"
    parsed = parse_curl(curl)
    assert parsed.method == HttpMethod.POST
    assert parsed.body_raw == ""
    assert parsed.body_json is None


def test_multiple_headers():
    curl = """curl -X GET https://api.example.com/api \\
    -H "Accept: application/json" \\
    -H "X-Custom: value1" \\
    -H "X-Custom: value2" \\
    -H "Authorization: Bearer tok" """
    parsed = parse_curl(curl)
    assert parsed.headers["Accept"] == "application/json"
    # last one wins
    assert parsed.headers["X-Custom"] == "value2"
    assert parsed.headers["Authorization"] == "Bearer tok"
