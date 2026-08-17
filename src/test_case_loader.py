from __future__ import annotations
import openpyxl
import logging
from pathlib import Path
from typing import List

from src.models import TestCase, TestCaseScope, TestCaseType, MutationType

logger = logging.getLogger(__name__)


def load_test_cases(filepath: str | Path, enabled_only: bool = True) -> List[TestCase]:
    """Load test cases from an Excel file and return validated pydantic models."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Test case file not found: {filepath}")

    wb = openpyxl.load_workbook(filepath, data_only=True)
    ws = wb.active
    if ws is None:
        raise ValueError(f"Workbook {filepath} has no active sheet")

    rows = list(ws.iter_rows(min_row=2, values_only=True))
    cases: List[TestCase] = []
    errors: List[str] = []

    for row_idx, row in enumerate(rows, start=2):
        if not row or row[0] is None:
            continue
        try:
            # Ensure we have at least 10 columns
            padded_row = list(row) + [None] * (10 - len(row))

            test_case = TestCase(
                test_case_id=str(padded_row[0] or ""),
                scope=TestCaseScope(str(padded_row[1] or "PayloadKey")),
                test_case_type=TestCaseType(str(padded_row[2] or "Validation")),
                description=str(padded_row[3] or ""),
                mutation_type=MutationType(str(padded_row[4] or "remove_key")),
                mutation_value=str(padded_row[5]) if padded_row[5] is not None else None,
                expected_status_code_range=str(padded_row[6] or ""),
                expected_behavior=str(padded_row[7] or ""),
                applies_to_mandatory_only=_parse_bool(padded_row[8], True),
                enabled=_parse_bool(padded_row[9], True),
            )
            cases.append(test_case)
        except Exception as e:
            errors.append(f"Row {row_idx}: {e}")

    if errors:
        for err in errors:
            logger.warning(f"Skipping test case row: {err}")

    if enabled_only:
        cases = [c for c in cases if c.enabled]

    logger.info(f"Loaded {len(cases)} test cases from {filepath}")
    return cases


def _parse_bool(value, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().upper()
    return s in ("TRUE", "YES", "1", "Y")
