# API Security & Validation Testing Framework

A CLI-based Python tool for QA engineers that automates manual API security and validation testing. Takes a curl command + optional encryption profile, runs header tests, detects mandatory payload keys, applies a configurable validation/vulnerability matrix, and produces an Excel report.

## Setup

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Seed default test cases

```bash
python -m src.cli seed-test-cases
```

Creates `test_cases/default_test_cases.xlsx` with 24 test cases covering auth, validation, boundary, and vulnerability scenarios.

### 2. Validate a curl command

```bash
python -m src.cli validate-curl --curl "curl -X POST https://api.example.com/users -H 'Content-Type: application/json' -d '{\"name\":\"test\"}'"
```

Or from a file:

```bash
python -m src.cli validate-curl --curl-file request.curl
```

### 3. Run the full test suite

```bash
python -m src.cli run --curl-file request.curl --output reports/report.xlsx
```

With a crypto profile:

```bash
python -m src.cli run --curl-file request.curl --crypto-profile config/crypto_profiles.yaml --profile-name default --output reports/report.xlsx
```

### 4. Run against the local mock server

```bash
# Start the server
python mock_server/app.py

# In another terminal, run the tests
python -m src.cli run --curl-file test_register.curl --output reports/report.xlsx
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `run` | Run full test suite against an API endpoint |
| `seed-test-cases` | Generate the default test case bank xlsx |
| `validate-curl` | Dry-run: parse a curl command and display structured request |

### `run` options

| Option | Description |
|--------|-------------|
| `--curl` | Inline curl command string |
| `--curl-file` | Path to file containing curl command |
| `--crypto-profile` | Path to crypto profiles YAML |
| `--profile-name` | Name of the crypto profile to use (default: "default") |
| `--test-cases` | Path to test cases xlsx (default: `test_cases/default_test_cases.xlsx`) |
| `--output, -o` | Output report path (default: `reports/report.xlsx`) |
| `--delay` | Delay between requests in ms (default: 200) |
| `--timeout` | Request timeout in seconds (default: 30) |

## How It Works

1. **Parse**: The curl command is parsed into a structured request (method, URL, headers, body, params).
2. **Baseline**: The original request is sent as ground truth.
3. **Header Tests**: All header-scope test cases (missing/invalid headers, auth token variations) run.
4. **Mandatory Detection**: For each payload key, remove it and resend. If the API rejects it → the key is mandatory.
5. **Payload Tests**: Validation/vulnerability test cases run against all mandatory keys.
6. **Report**: Results written to an Excel file with conditional highlighting.

## Project Structure

```
api-test-framework/
├── README.md
├── requirements.txt
├── config/
│   ├── crypto_profiles.yaml
│   └── settings.yaml
├── test_cases/
│   └── default_test_cases.xlsx
├── scripts/
│   ├── seed_test_cases.py
│   ├── integration_test.py
│   └── run_server.py
├── src/
│   ├── cli.py                 # Click CLI entry point
│   ├── models.py              # Pydantic models
│   ├── curl_parser.py         # Custom curl parser via shlex
│   ├── crypto_adapter.py      # AES encrypt/decrypt with pass-through mode
│   ├── request_builder.py     # Build mutated requests
│   ├── mandatory_detector.py  # Detect mandatory payload keys
│   ├── test_case_loader.py    # Read xlsx into pydantic models
│   ├── payload_mutator.py     # Dispatch table of mutation functions
│   ├── test_engine.py         # Orchestrator
│   └── report_generator.py    # Excel report with conditional formatting
├── mock_server/
│   └── app.py                 # Flask test server
├── reports/
└── tests/
    ├── test_curl_parser.py
    ├── test_crypto_adapter.py
    ├── test_mandatory_detector.py
    └── test_payload_mutator.py
```

## Crypto Profiles

Configured via YAML. Supports:

- **Algorithms**: AES-256-CBC, AES-256-GCM, AES-128-CBC
- **Key derivation**: PBKDF2HMAC or raw key
- **Output encoding**: base64 or hex
- **IV**: random generation or literal value

Example profile:

```yaml
profiles:
  - name: default
    algorithm: AES-256-CBC
    key_derivation: PBKDF2HMAC
    hash: SHA256
    iterations: 10000
    key: "my-secret-api-key-12345"
    key_encoding: utf8
    salt: "fixed-salt-value"
    output_encoding: base64
```

When no profile is provided, the adapter runs in **pass-through mode** (no encryption), so the tool works for plain APIs too.

## Test Case Bank

The default test case bank (`test_cases/default_test_cases.xlsx`) contains 24 seed cases:

- **Auth**: Missing/invalid/expired auth tokens
- **Validation**: Missing Content-Type, invalid values
- **Boundary**: Oversized strings, zero-length, max-length, negative numbers
- **Vulnerability**: SQL injection, XSS, special chars, unicode/emoji
- **Negative**: Wrong data types

Adding a new row to the xlsx and rerunning requires zero code changes.

## Mutations

The `payload_mutator.py` dispatch table covers:

- `remove_key`, `empty_value`, `null_value`
- `alpha_only`, `numeric_only`, `special_chars`
- `max_length_exceed`, `min_length_violate`
- `sql_injection`, `xss_payload`, `oversized_payload`
- `unicode_emoji`, `wrong_type`
- `header_missing`, `header_invalid_value`
- `auth_token_missing`, `auth_token_invalid`, `auth_token_expired`

All mutations support nested JSON via dot-path addressing (e.g., `user.address.zip`).

## Report Format

Generated `.xlsx` with columns: `API | Key | TestCase | TestCaseType | Status | Mandatory | StatusCode`.

- **Conditional highlighting**: Vulnerability rows where the malicious payload was **accepted** are highlighted red (actionable signal).
- Auto-filter, frozen header row, reasonable column widths.
- One sheet per endpoint.

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Extending

### Adding a new MutationType

1. Add the name to `MutationType` enum in `models.py`.
2. Write a mutation function in `payload_mutator.py`.
3. Add to `MUTATION_DISPATCH` dict.
4. Add corresponding test case rows to the xlsx.
5. (Optional) Add `import` reference in `is_header_mutation` if it's a header mutation.

### Adding a new crypto algorithm

1. Add to `Algorithm` enum in `models.py`.
2. Implement encrypt/decrypt logic in `crypto_adapter.py`.
3. Write round-trip unit tests.

## Curl Parser Decision

The tool uses a **custom shlex-based parser** (not `uncurl`) because:
- `uncurl` struggles with multi-line curls containing `\` continuations
- `uncurl` has issues with `--data-raw`, `--data-binary`, and multiple `-H` flags
- Custom parser provides full control and predictable behavior

## Out of Scope (v1)

- No GUI/web dashboard
- No multipart/form-data file upload testing
- No GraphQL support (REST/JSON only)
- No parallel/concurrent execution — sequential only
