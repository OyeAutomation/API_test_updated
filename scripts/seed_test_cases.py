#!/usr/bin/env python3
"""Generate the default_test_cases.xlsx test case bank."""

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
import os


def create_test_cases_xlsx(output_path: str):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "TestCases"

    headers = [
        "TestCaseID", "Scope", "TestCaseType", "Description",
        "MutationType", "MutationValue", "ExpectedStatusCodeRange",
        "ExpectedBehavior", "AppliesToMandatoryOnly", "Enabled"
    ]

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin"),
    )

    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border

    test_cases = [
        # --- Header scope ---
        ("HDR-001", "Header", "Auth", "Missing Authorization header",
         "header_missing", "Authorization", "401-401",
         "API should reject requests without auth token", "FALSE", "TRUE"),
        ("HDR-002", "Header", "Auth", "Invalid/expired auth token (Bearer xyz)",
         "auth_token_invalid", "Bearer invalid_token_12345", "401-401",
         "API should reject invalid auth tokens", "FALSE", "TRUE"),
        ("HDR-003", "Header", "Auth", "Expired auth token pattern (Bearer expired)",
         "auth_token_expired", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9", "401-401",
         "API should reject expired tokens", "FALSE", "TRUE"),
        ("HDR-004", "Header", "Validation", "Missing Content-Type header",
         "header_missing", "Content-Type", "400-415",
         "API should reject requests without Content-Type for POST/PUT", "FALSE", "TRUE"),
        ("HDR-005", "Header", "Validation", "Invalid Content-Type header value",
         "header_invalid_value", "Content-Type:text/plain", "400-415",
         "API should reject non-JSON Content-Type", "FALSE", "TRUE"),

        # --- Payload scope (mandatory only) ---
        ("VAL-001", "PayloadKey", "Validation", "Remove key entirely",
         "remove_key", "", "400-499",
         "API should reject request with missing mandatory field", "TRUE", "TRUE"),
        ("VAL-002", "PayloadKey", "Validation", "Empty string value",
         "empty_value", "", "400-499",
         "API should reject empty string for mandatory field", "TRUE", "TRUE"),
        ("VAL-003", "PayloadKey", "Validation", "Null value",
         "null_value", "", "400-499",
         "API should reject null value for mandatory field", "TRUE", "TRUE"),
        ("VAL-004", "PayloadKey", "Boundary", "Alpha-only characters (a-zA-Z)",
         "alpha_only", "abcdefGHIJKL", "400-499",
         "API should reject alphabetic-only input for numeric/structured fields", "TRUE", "TRUE"),
        ("VAL-005", "PayloadKey", "Boundary", "Numeric-only characters (0-9)",
         "numeric_only", "1234567890", "400-499",
         "API should reject numeric-only input for string fields expecting text", "TRUE", "TRUE"),
        ("VAL-006", "PayloadKey", "Vulnerability", "Special character injection",
         "special_chars", "!@#$%^&*()_+{}|:\"<>?~", "400-499",
         "API should reject or sanitize special characters", "TRUE", "TRUE"),
        ("VAL-007", "PayloadKey", "Vulnerability", "SQL injection (string context)",
         "sql_injection", "' OR '1'='1", "400-499",
         "API should reject SQL injection payloads", "TRUE", "TRUE"),
        ("VAL-008", "PayloadKey", "Vulnerability", "SQL injection (numeric context)",
         "sql_injection", "1; DROP TABLE users", "400-499",
         "API should reject SQL injection payloads", "TRUE", "TRUE"),
        ("VAL-009", "PayloadKey", "Vulnerability", "XSS payload injection",
         "xss_payload", "<script>alert('xss')</script>", "400-499",
         "API should reject XSS injection payloads", "TRUE", "TRUE"),
        ("VAL-010", "PayloadKey", "Boundary", "Oversized string (10,000 chars)",
         "max_length_exceed", "", "400-499",
         "API should reject excessively long strings", "TRUE", "TRUE"),
        ("VAL-011", "PayloadKey", "Boundary", "Min length violation (0-length string)",
         "min_length_violate", "", "400-499",
         "API should reject zero-length strings for mandatory fields", "TRUE", "TRUE"),
        ("VAL-012", "PayloadKey", "Negative", "Wrong data type (string in int field)",
         "wrong_type", "not_an_integer", "400-499",
         "API should reject type mismatches", "TRUE", "TRUE"),
        ("VAL-013", "PayloadKey", "Boundary", "Negative number for numeric field",
         "numeric_only", "-1", "400-499",
         "API should reject negative values if not allowed", "TRUE", "TRUE"),
        ("VAL-014", "PayloadKey", "Boundary", "Zero value for numeric field",
         "numeric_only", "0", "400-499",
         "API should validate zero boundary", "TRUE", "TRUE"),
        ("VAL-015", "PayloadKey", "Vulnerability", "Unicode/emoji injection",
         "unicode_emoji", "Hello World 👋🔥💯", "400-499",
         "API should reject or sanitize unicode injection", "TRUE", "TRUE"),
        ("VAL-016", "PayloadKey", "Boundary", "255 character boundary test",
         "max_length_exceed", "", "400-499",
         "API should enforce reasonable max length", "TRUE", "TRUE"),
        ("VAL-017", "PayloadKey", "Vulnerability", "Oversized payload blob",
         "oversized_payload", "", "400-499",
         "API should reject oversized payloads", "TRUE", "TRUE"),

        # --- Global scope ---
        ("GLB-001", "Global", "Validation", "Malformed JSON body",
         "special_chars", "{invalid_json: }", "400-499",
         "API should reject malformed JSON", "FALSE", "TRUE"),
        ("GLB-002", "Global", "Auth", "Auth token missing (Bearer)",
         "auth_token_missing", "", "401-401",
         "API should reject missing auth header", "FALSE", "TRUE"),
    ]

    for row_idx, case in enumerate(test_cases, 2):
        for col_idx, value in enumerate(case, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            cell.alignment = Alignment(vertical="center")

    # Auto-width
    for col_idx, header in enumerate(headers, 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx)].width = 22

    # Freeze top row
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{openpyxl.utils.get_column_letter(len(headers))}{len(test_cases) + 1}"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wb.save(output_path)
    print(f"Created test case bank: {output_path} with {len(test_cases)} cases")


if __name__ == "__main__":
    output = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_cases", "default_test_cases.xlsx")
    create_test_cases_xlsx(output)
