from __future__ import annotations
import logging
from pathlib import Path
from typing import List, Dict

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

from src.models import TestResult

logger = logging.getLogger(__name__)

HEADER_COLUMNS = ["API", "TestCase ID", "Key", "TestCase", "TestCaseType", "Status", "Mandatory", "StatusCode", "Response", "Decrypted Response", "Decrypted Payload Sent", "Encrypted Payload"]
HEADER_FILL = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
RED_FILL = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
RED_FONT = Font(color="9C0006")
GREEN_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
GREEN_FONT = Font(color="006100")
YELLOW_FILL = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
YELLOW_FONT = Font(color="9C6500")
THIN_BORDER = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin"),
)


def generate_report(
    results: Dict[str, List[TestResult]],
    output_path: str | Path,
):
    """Generate an Excel report from test results.

    Args:
        results: Dict mapping endpoint/API name -> list of TestResult
        output_path: Path to write the xlsx file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    used_sheet_names: set = set()

    if not results:
        # No results at all — write a placeholder sheet instead of crashing
        ws = wb.create_sheet(title="No Results")
        _write_headers(ws)
        cell = ws.cell(row=2, column=1, value="No test results were produced. "
                       "Check the test case file and the curl command.")
        cell.alignment = Alignment(vertical="center", wrap_text=True)
        ws.freeze_panes = "A2"
        ws.column_dimensions["A"].width = 80
        wb.save(str(output_path))
        logger.info(f"Report written to {output_path} (no results)")
        return

    for api_label, api_results in results.items():
        sheet_name = _unique_sheet_name(api_label, used_sheet_names)
        ws = wb.create_sheet(title=sheet_name)

        # Write headers
        _write_headers(ws)

        # Write data rows
        for row_idx, result in enumerate(api_results, 2):
            values = [
                result.api,
                result.test_case_id,
                result.key,
                result.test_case,
                result.test_case_type,
                result.status,
                result.mandatory,
                result.status_code,
                result.response,
                result.decrypted_response,
                result.decrypted_payload,
                result.encrypted_payload,
            ]
            for col_idx, value in enumerate(values, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=_safe_cell_value(value))
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="center", wrap_text=(col_idx in (6, 9, 10, 11, 12)))

            # Apply conditional highlighting
            _apply_highlighting(ws, row_idx, result)

        # Auto-filter
        last_col = get_column_letter(len(HEADER_COLUMNS))
        last_row = len(api_results) + 1
        ws.auto_filter.ref = f"A1:{last_col}{last_row}"

        # Frozen header row
        ws.freeze_panes = "A2"

        # Auto-width columns
        _set_column_widths(ws, api_results)

    wb.save(str(output_path))
    logger.info(f"Report written to {output_path}")


def _write_headers(ws):
    for col_idx, header in enumerate(HEADER_COLUMNS, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = THIN_BORDER


def _safe_cell_value(value):
    """Neutralize Excel formula injection from untrusted strings.

    Excel evaluates cells beginning with =, +, - or @ as formulas.
    """
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _apply_highlighting(ws, row_idx: int, result: TestResult):
    """Apply conditional formatting to a result row."""
    test_case_type = result.test_case_type
    status_code = result.status_code
    status = result.status or ""

    # Yellow: contract violations — API rejected via business status but
    # surfaced the rejection with a success HTTP code (2xx)
    if status.startswith("DEFECT"):
        for col_idx in range(1, len(HEADER_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.fill = YELLOW_FILL
            cell.font = YELLOW_FONT
    # Red: Vulnerability tcs where the payload was actually accepted
    # (2xx and not a DEFECT row — DEFECT means it was rejected at business
    # level but surfaced with a success HTTP code)
    elif test_case_type == "Vulnerability" and 0 < status_code < 400 and not status.startswith("DEFECT"):
        for col_idx in range(1, len(HEADER_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.fill = RED_FILL
            cell.font = RED_FONT
    # Green: Vulnerability tcs where the API properly rejected the payload (4xx only —
    # 5xx server errors are not a security pass)
    elif test_case_type == "Vulnerability" and 400 <= status_code <= 499:
        for col_idx in range(1, len(HEADER_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.fill = GREEN_FILL
            cell.font = GREEN_FONT


def _set_column_widths(ws, results: List[TestResult]):
    """Set reasonable column widths based on content."""
    widths = {
        1: 40,   # API
        2: 14,   # TestCase ID
        3: 20,   # Key
        4: 40,   # TestCase (description)
        5: 16,   # TestCaseType
        6: 50,   # Status
        7: 12,   # Mandatory
        8: 12,   # StatusCode
        9: 60,   # Response
        10: 60,  # Decrypted Response
        11: 60,  # Decrypted Payload Sent
        12: 60,  # Encrypted Payload
    }
    for col_idx, width in widths.items():
        ws.column_dimensions[get_column_letter(col_idx)].width = width


def _sanitize_sheet_name(name: str) -> str:
    """Sanitize a string for use as an Excel sheet name (max 31 chars, no []:*?/)."""
    if not name:
        name = "API"
    invalid_chars = ['[', ']', ':', '*', '?', '/', '\\']
    for c in invalid_chars:
        name = name.replace(c, '_')
    # Truncate to 31 chars (Excel limit)
    if len(name) > 31:
        name = name[:28] + "..."
    return name


def _unique_sheet_name(name: str, used: set) -> str:
    """Return a sanitized, non-colliding sheet name."""
    base = _sanitize_sheet_name(name)
    candidate = base
    counter = 2
    while candidate in used:
        suffix = f" ({counter})"
        candidate = base[:31 - len(suffix)] + suffix
        counter += 1
    used.add(candidate)
    return candidate
