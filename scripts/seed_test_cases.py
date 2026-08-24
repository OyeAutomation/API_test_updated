#!/usr/bin/env python3
"""Generate the default_test_cases.xlsx test case bank.

The bank is generated from the built-in universal suite
(src/test_cases_builtin.py), so the seed and the engine can never drift:
the same checks the engine always runs are exactly what the xlsx contains.
"""

import os
import sys

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.test_cases_builtin import BUILTIN_TEST_CASES


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
        (
            tc.test_case_id,
            tc.scope.value,
            tc.test_case_type.value,
            tc.description,
            tc.mutation_type.value,
            tc.mutation_value or "",
            tc.expected_status_code_range or "",
            tc.expected_behavior,
            "TRUE" if tc.applies_to_mandatory_only else "FALSE",
            "TRUE" if tc.enabled else "FALSE",
        )
        for tc in BUILTIN_TEST_CASES
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
