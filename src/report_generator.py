from __future__ import annotations
import logging
from pathlib import Path
from typing import List, Dict

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

from src.models import TestResult

logger = logging.getLogger(__name__)

HEADER_COLUMNS = ["API", "Key", "TestCase", "TestCaseType", "Status", "Mandatory", "StatusCode", "Response", "Decrypted Response", "Decrypted Payload Sent", "Encrypted Payload"]
HEADER_FILL = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
RED_FILL = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
RED_FONT = Font(color="9C0006")
GREEN_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
GREEN_FONT = Font(color="006100")
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

    for api_label, api_results in results.items():
        ws = wb.create_sheet(title=_sanitize_sheet_name(api_label))

        # Write headers
        for col_idx, header in enumerate(HEADER_COLUMNS, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = THIN_BORDER

        # Write data rows
        for row_idx, result in enumerate(api_results, 2):
            values = [
                result.api,
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
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="center", wrap_text=(col_idx in (5, 8, 9, 10, 11)))

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


def _apply_highlighting(ws, row_idx: int, result: TestResult):
    """Apply conditional formatting to a result row."""
    test_case_type = result.test_case_type
    status = result.status
    status_code = result.status_code

    # Red: Vulnerability tcs where payload was accepted (status < 400)
    if test_case_type == "Vulnerability" and status_code < 400 and status_code > 0:
        for col_idx in range(1, len(HEADER_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.fill = RED_FILL
            cell.font = RED_FONT
    # Green: Vulnerability tcs where payload was rejected (status >= 400)
    elif test_case_type == "Vulnerability" and status_code >= 400:
        for col_idx in range(1, len(HEADER_COLUMNS) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.fill = GREEN_FILL
            cell.font = GREEN_FONT


def _set_column_widths(ws, results: List[TestResult]):
    """Set reasonable column widths based on content."""
    widths = {
        1: 40,   # API
        2: 20,   # Key
        3: 40,   # TestCase (description)
        4: 16,   # TestCaseType
        5: 50,   # Status
        6: 12,   # Mandatory
        7: 12,   # StatusCode
        8: 60,   # Response
        9: 60,   # Decrypted Response
        10: 60,  # Decrypted Payload Sent
        11: 60,  # Encrypted Payload
    }
    for col_idx, width in widths.items():
        ws.column_dimensions[get_column_letter(col_idx)].width = width


def _sanitize_sheet_name(name: str) -> str:
    """Sanitize a string for use as an Excel sheet name (max 31 chars, no []:*?/)."""
    invalid_chars = ['[', ']', ':', '*', '?', '/', '\\']
    for c in invalid_chars:
        name = name.replace(c, '_')
    # Truncate to 31 chars (Excel limit)
    if len(name) > 31:
        name = name[:28] + "..."
    return name
