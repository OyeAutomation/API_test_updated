"""Tests for the mock server using Flask's test client (no sockets needed)."""
import pytest


@pytest.fixture
def client():
    from mock_server.app import app
    app.config["TESTING"] = True
    return app.test_client()


def _valid_register_body():
    return '{"username":"john","email":"john@test.com","password":"secret123"}'


def test_register_success(client):
    resp = client.post("/api/register", data=_valid_register_body(),
                       content_type="application/json")
    assert resp.status_code == 201


def test_register_missing_content_type_rejected(client):
    """HDR-004: the mock must respect Content-Type (no force=True)."""
    resp = client.post("/api/register", data=_valid_register_body())
    assert resp.status_code == 415


def test_register_wrong_content_type_rejected(client):
    """HDR-005: text/plain body must not be parsed as JSON."""
    resp = client.post("/api/register", data=_valid_register_body(),
                       content_type="text/plain")
    assert resp.status_code == 415


def test_register_malformed_json_rejected(client):
    """GLB-001: malformed JSON with json Content-Type must be rejected."""
    resp = client.post("/api/register", data='{"username": "broken',
                       content_type="application/json")
    assert resp.status_code in (400, 415)


def test_register_missing_field(client):
    resp = client.post("/api/register",
                       data='{"username":"john","email":"john@test.com"}',
                       content_type="application/json")
    assert resp.status_code == 400
    assert b"password" in resp.data


def test_register_sql_injection_rejected(client):
    resp = client.post("/api/register",
                       data='{"username":"john\' OR \'1\'=\'1","email":"john@test.com","password":"secret123"}',
                       content_type="application/json")
    assert resp.status_code == 400


def test_register_xss_rejected(client):
    resp = client.post("/api/register",
                       data='{"username":"<script>alert(1)</script>","email":"john@test.com","password":"secret123"}',
                       content_type="application/json")
    assert resp.status_code == 400


def test_order_requires_numeric_amount(client):
    resp = client.post("/api/order",
                       data='{"product_id":"p1","amount":"100"}',
                       content_type="application/json")
    assert resp.status_code == 400


def test_order_amount_boundary(client):
    resp = client.post("/api/order",
                       data='{"product_id":"p1","amount":10001}',
                       content_type="application/json")
    assert resp.status_code == 400


def test_protected_requires_valid_token(client):
    assert client.get("/api/protected").status_code == 401
    assert client.get("/api/protected",
                      headers={"Authorization": "Bearer valid-token-12345"}).status_code == 200


def test_nested_endpoint_requires_nested_fields(client):
    body = '{"user":{"name":"john","email":"john@test.com"}}'
    resp = client.post("/api/register/nested", data=body, content_type="application/json")
    assert resp.status_code == 400


def test_nested_endpoint_injection_rejected(client):
    body = ('{"user":{"name":"<script>alert(1)</script>",'
            '"email":"john@test.com","address":{"zip":"12345"}}}')
    resp = client.post("/api/register/nested", data=body, content_type="application/json")
    assert resp.status_code == 400