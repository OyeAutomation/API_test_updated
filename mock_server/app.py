#!/usr/bin/env python3
"""
Small Flask mock server for local testing of the API test framework.

Endpoints:
  POST /api/register        - Has required fields: username, email, password
  POST /api/order            - Has required field: amount (numeric), product_id
  GET /api/protected         - Requires Authorization: Bearer <valid-token>
"""
import json
from typing import Optional
from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_TOKEN = "valid-token-12345"

UNSAFE_CHARS = set("!@#$%^&*()+{}|:\"<>?~'`;\\,[]=")
MAX_STRING_LENGTH = 255

ALLOWED_ITEM_STATUSES = ("active", "inactive")
_seen_order_refs: set = set()


@app.after_request
def add_security_headers(resp):
    """Demo middleware: security headers all endpoints should send."""
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'")
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


def _reject_unsafe_strings(data: dict, exempt: tuple = ()) -> Optional[str]:
    """Return an error message if any (nested) string field carries special
    chars, unicode/emoji, or an oversized value. Exempted keys (e.g. email,
    which has its own format check) are skipped."""

    def _scan(value, path: str) -> Optional[str]:
        if isinstance(value, dict):
            for k, v in value.items():
                if k in exempt:
                    continue
                found = _scan(v, f"{path}.{k}" if path else k)
                if found:
                    return found
        elif isinstance(value, list):
            for idx, v in enumerate(value):
                found = _scan(v, f"{path}[{idx}]")
                if found:
                    return found
        elif isinstance(value, str):
            if len(value) > MAX_STRING_LENGTH:
                return f"{path} exceeds maximum length of {MAX_STRING_LENGTH}"
            if any(ord(c) > 0x7E for c in value):
                return f"{path} contains unsupported unicode characters"
            if any(c in UNSAFE_CHARS for c in value):
                return f"{path} contains disallowed characters"
        return None

    return _scan(data, "")


def _valid_email(v: str) -> bool:
    if not isinstance(v, str) or "@" not in v or "." not in v.rsplit("@", 1)[-1]:
        return False
    local, _, domain = v.partition("@")
    return bool(local) and bool(domain) and " " not in v


def require_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth.split(" ", 1)[1] == VALID_TOKEN


@app.route("/api/register", methods=["POST"])
def register():
    data = _json_body()
    if data is None:
        return jsonify({"error": "Missing or invalid JSON body (requires Content-Type: application/json)"}), 415

    required = ["username", "email", "password"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}", "field": field}), 400

    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")

    # Validation checks
    if not isinstance(username, str) or len(username.strip()) == 0:
        return jsonify({"error": "Username must be a non-empty string"}), 400
    if not _valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # SQLi / XSS / special chars / unicode / oversized (simplified)
    body_str = json.dumps(data).lower()
    if "or '1'='1" in body_str or "<script>" in body_str:
        return jsonify({"error": "Malicious input detected"}), 400
    unsafe = _reject_unsafe_strings(data, exempt=("email",))
    if unsafe:
        return jsonify({"error": unsafe}), 400

    return jsonify({"message": "User registered", "username": username}), 201


@app.route("/api/items", methods=["GET"])
def list_items():
    """Paginated list endpoint with query-param validation."""
    page = request.args.get("page", "1")
    status = request.args.get("status", "")

    try:
        page_num = int(page)
    except (TypeError, ValueError):
        return jsonify({"error": "page must be an integer", "field": "page"}), 400
    if page_num < 1:
        return jsonify({"error": "page must be >= 1", "field": "page"}), 400
    if status and status not in ALLOWED_ITEM_STATUSES:
        return jsonify({"error": f"status must be one of {ALLOWED_ITEM_STATUSES}", "field": "status"}), 400

    items = [{"id": i, "name": f"item-{i}", "status": "active"} for i in range(1, 21)]
    return jsonify({"success": 1, "message": "Data fetched", "data": items, "page": page_num}), 200


@app.route("/api/order", methods=["POST"])
def create_order():
    global _seen_order_refs
    data = _json_body()
    if data is None:
        return jsonify({"error": "Missing or invalid JSON body (requires Content-Type: application/json)"}), 415

    required = ["product_id", "amount"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}", "field": field}), 400

    # Duplicate-prevention check: an order_ref idempotency key seen before is
    # rejected as a duplicate (client-generated key, realistic scheme).
    order_ref = data.get("order_ref")
    if order_ref is not None:
        if order_ref in _seen_order_refs:
            return jsonify({"error": "Duplicate order submission", "field": "order_ref"}), 409
        _seen_order_refs.add(order_ref)

    product_id = data.get("product_id")
    amount = data.get("amount")

    if not isinstance(product_id, str) or len(product_id.strip()) == 0:
        return jsonify({"error": "product_id must be a non-empty string"}), 400

    if not isinstance(amount, (int, float)) or isinstance(amount, bool):
        return jsonify({"error": "amount must be a number"}), 400

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    if amount > 10000:
        return jsonify({"error": "amount exceeds maximum"}), 400

    # SQLi / XSS / special chars / unicode / oversized
    body_str = json.dumps(data).lower()
    if "drop table" in body_str or "or '1'='1" in body_str or "<script>" in body_str:
        return jsonify({"error": "Malicious input detected"}), 400
    unsafe = _reject_unsafe_strings(data)
    if unsafe:
        return jsonify({"error": unsafe}), 400

    return jsonify({"message": "Order created", "order_id": "ORD-001", "amount": amount}), 201


@app.route("/api/protected", methods=["GET"])
def protected():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"message": "Welcome to the protected resource", "user": "test_user"}), 200


@app.route("/api/register/nested", methods=["POST"])
def register_nested():
    """Endpoint with nested required fields for deeper testing."""
    data = _json_body()
    if data is None:
        return jsonify({"error": "Missing or invalid JSON body (requires Content-Type: application/json)"}), 415

    # Required: user.name, user.email, user.address.zip
    user = data.get("user")
    if not isinstance(user, dict):
        return jsonify({"error": "Missing required object: user", "field": "user"}), 400

    if "name" not in user:
        return jsonify({"error": "Missing required field: user.name", "field": "user.name"}), 400
    if not isinstance(user["name"], str):
        return jsonify({"error": "Invalid type for user.name (expected string)", "field": "user.name"}), 400
    if "email" not in user or not _valid_email(user["email"]):
        return jsonify({"error": "Missing or invalid user.email", "field": "user.email"}), 400

    address = user.get("address")
    if not isinstance(address, dict):
        return jsonify({"error": "Missing required object: user.address", "field": "user.address"}), 400
    if "zip" not in address:
        return jsonify({"error": "Missing required field: user.address.zip", "field": "user.address.zip"}), 400
    if not isinstance(address["zip"], str):
        return jsonify({"error": "Invalid type for user.address.zip (expected string)", "field": "user.address.zip"}), 400

    # SQLi / XSS / special chars / unicode / oversized (consistent with other endpoints)
    body_str = json.dumps(data).lower()
    if "or '1'='1" in body_str or "<script>" in body_str or "drop table" in body_str:
        return jsonify({"error": "Malicious input detected"}), 400
    unsafe = _reject_unsafe_strings(data, exempt=("email",))
    if unsafe:
        return jsonify({"error": unsafe}), 400

    return jsonify({"message": "User registered with nested data", "user": user["name"]}), 201


def _json_body():
    """Parse a JSON body only when Content-Type is application/json.

    Mirrors the test bank expectations: missing/invalid Content-Type must be
    rejected (HDR-004/HDR-005), not silently parsed.
    """
    ct = request.headers.get("Content-Type", "")
    if "application/json" not in ct.lower():
        return None
    return request.get_json(silent=True)


if __name__ == "__main__":
    print("Mock server starting on http://localhost:5000")
    print("Endpoints:")
    print("  POST /api/register")
    print("  POST /api/order")
    print("  POST /api/register/nested")
    print("  GET  /api/protected (Authorization: Bearer valid-token-12345)")
    app.run(debug=True, port=5000)
