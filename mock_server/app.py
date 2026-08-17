#!/usr/bin/env python3
"""
Small Flask mock server for local testing of the API test framework.

Endpoints:
  POST /api/register        - Has required fields: username, email, password
  POST /api/order            - Has required field: amount (numeric), product_id
  GET /api/protected         - Requires Authorization: Bearer <valid-token>
"""
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_TOKEN = "valid-token-12345"


def require_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth.split(" ", 1)[1] == VALID_TOKEN


@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if data is None:
        return jsonify({"error": "Request body is required"}), 400

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
    if not isinstance(email, str) or "@" not in email:
        return jsonify({"error": "Invalid email format"}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # SQLi / XSS detection (simplified)
    body_str = json.dumps(data).lower()
    if "or '1'='1" in body_str or "<script>" in body_str:
        return jsonify({"error": "Malicious input detected"}), 400

    return jsonify({"message": "User registered", "username": username}), 201


@app.route("/api/order", methods=["POST"])
def create_order():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if data is None:
        return jsonify({"error": "Request body is required"}), 400

    required = ["product_id", "amount"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}", "field": field}), 400

    product_id = data.get("product_id")
    amount = data.get("amount")

    if not isinstance(product_id, str) or len(product_id.strip()) == 0:
        return jsonify({"error": "product_id must be a non-empty string"}), 400

    if not isinstance(amount, (int, float)):
        return jsonify({"error": "amount must be a number"}), 400

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    if amount > 10000:
        return jsonify({"error": "amount exceeds maximum"}), 400

    # SQLi check
    body_str = json.dumps(data).lower()
    if "drop table" in body_str or "or '1'='1" in body_str:
        return jsonify({"error": "Malicious input detected"}), 400

    return jsonify({"message": "Order created", "order_id": "ORD-001", "amount": amount}), 201


@app.route("/api/protected", methods=["GET"])
def protected():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"message": "Welcome to the protected resource", "user": "test_user"}), 200


@app.route("/api/register/nested", methods=["POST"])
def register_nested():
    """Endpoint with nested required fields for deeper testing."""
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if data is None:
        return jsonify({"error": "Request body is required"}), 400

    # Required: user.name, user.email, user.address.zip
    user = data.get("user")
    if not isinstance(user, dict):
        return jsonify({"error": "Missing required object: user", "field": "user"}), 400

    if "name" not in user:
        return jsonify({"error": "Missing required field: user.name", "field": "user.name"}), 400
    if "email" not in user:
        return jsonify({"error": "Missing required field: user.email", "field": "user.email"}), 400

    address = user.get("address")
    if not isinstance(address, dict):
        return jsonify({"error": "Missing required object: user.address", "field": "user.address"}), 400
    if "zip" not in address:
        return jsonify({"error": "Missing required field: user.address.zip", "field": "user.address.zip"}), 400

    return jsonify({"message": "User registered with nested data", "user": user["name"]}), 201


if __name__ == "__main__":
    print("Mock server starting on http://localhost:5000")
    print("Endpoints:")
    print("  POST /api/register")
    print("  POST /api/order")
    print("  POST /api/register/nested")
    print("  GET  /api/protected (Authorization: Bearer valid-token-12345)")
    app.run(debug=True, port=5000)
