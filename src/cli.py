from __future__ import annotations
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from src.models import Settings, TestResult
from src.curl_parser import parse_curl
from src.test_engine import run_suite
from src.report_generator import generate_report

console = Console()
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
def cli(verbose: bool):
    """API Security & Validation Testing Framework"""
    setup_logging(verbose)


@cli.command()
@click.option("--curl", "curl_inline", type=str, help="Inline curl command string")
@click.option("--curl-file", type=click.Path(exists=True, dir_okay=False), help="Path to file containing curl command")
@click.option("--curl-dir", type=click.Path(exists=True, file_okay=False), help="Directory with .curl files to batch process")
@click.option("--crypto-profile", type=click.Path(exists=True, dir_okay=False), help="Path to crypto profiles YAML")
@click.option("--profile-name", type=str, default="default", help="Name of the crypto profile to use (for request payload)")
@click.option("--response-profile-name", type=str, default=None, help="Separate profile for response decryption")
@click.option("--test-cases", type=click.Path(exists=True, dir_okay=False), default=None, help="Path to test cases xlsx")
@click.option("--output", "-o", type=click.Path(), default="reports/report.xlsx", help="Output report path")
@click.option("--delay", type=int, default=200, help="Delay between requests in ms")
@click.option("--timeout", type=int, default=30, help="Request timeout in seconds")
@click.option("--include-non-mandatory", is_flag=True, help="Also test non-mandatory payload keys")
def run(curl_inline: Optional[str], curl_file: Optional[str], curl_dir: Optional[str],
        crypto_profile: Optional[str], profile_name: str, response_profile_name: Optional[str],
        test_cases: Optional[str], output: str, delay: int, timeout: int,
        include_non_mandatory: bool):
    """Run the full test suite against one or more API endpoints."""
    crypto_config = _load_crypto_profile(crypto_profile, profile_name)
    response_crypto_config = (
        _load_crypto_profile(crypto_profile, response_profile_name)
        if response_profile_name else None
    )

    if not test_cases:
        default_path = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
        if default_path.exists():
            test_cases = str(default_path)

    settings = Settings(request_delay_ms=delay, timeout_seconds=timeout,
                        include_non_mandatory=include_non_mandatory)

    if curl_dir:
        # Batch mode: process all .curl files and generate individual reports
        curl_files = sorted(Path(curl_dir).glob("*.curl"))
        if not curl_files:
            console.print(f"[red]No .curl files found in {curl_dir}[/red]")
            sys.exit(1)
        console.print(f"[bold]Found {len(curl_files)} curl files in {curl_dir}[/bold]\n")

        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)

        all_results: List[TestResult] = []
        for cf in curl_files:
            cmd = cf.read_text(encoding="utf-8").strip()
            if not cmd:
                continue
            console.print(f"[bold cyan]Processing:[/bold cyan] {cf.name}")
            try:
                parsed = parse_curl(cmd)
                results = _process_single_curl(cmd, crypto_config, test_cases, settings,
                                               response_crypto_config=response_crypto_config)
                # Generate individual report
                grouped = {parsed.url: results}
                report_path = output_dir / f"{cf.stem}.xlsx"
                generate_report(grouped, str(report_path))
                console.print(f"  [green]-> {len(results)} tests -> {report_path.name}[/green]")
                all_results.extend(results)
            except Exception as e:
                console.print(f"  [red]Failed:[/red] {e}")

        if not all_results:
            console.print("[red]No results from any curl file.[/red]")
            sys.exit(1)

        results = all_results
    else:
        # Single mode
        curl_command = _read_curl(curl_inline, curl_file)
        if not curl_command:
            console.print("[red]Error:[/red] Provide --curl, --curl-file, or --curl-dir")
            sys.exit(1)

        results = _process_single_curl(curl_command, crypto_config, test_cases, settings,
                                       response_crypto_config=response_crypto_config)

    if not curl_dir:
        # Group results by API endpoint & generate combined report (single mode only)
        grouped: Dict[str, List[TestResult]] = {}
        for r in results:
            grouped.setdefault(r.api, []).append(r)

        console.print(f"\n[bold green]Generating report:[/bold green] {output}")
        generate_report(grouped, output)
    else:
        console.print(f"\n[bold green]Reports written to:[/bold green] {output_dir}/")

    # Summary
    total = len(results)
    vuln_accepted = sum(
        1 for r in results
        if r.test_case_type == "Vulnerability" and 0 < r.status_code < 400
    )
    errors = sum(1 for r in results if r.test_case_type == "Error")
    console.print(f"\n[bold]Results:[/bold] {total} total | "
                  f"[red]{vuln_accepted} vulnerabilities accepted[/red] | "
                  f"[yellow]{errors} errors[/yellow]")


def _process_single_curl(
    curl_command: str, crypto_config: Optional[Dict], test_cases: Optional[str],
    settings: Settings, response_crypto_config: Optional[Dict] = None,
) -> List[TestResult]:
    """Parse a curl command and run the test suite. Returns results list."""
    try:
        parsed = parse_curl(curl_command)
    except Exception as e:
        console.print(f"[red]Error parsing curl command:[/red] {e}")
        raise

    console.print(f"  [bold]API:[/bold] {parsed.method} {parsed.url}")
    console.print(f"  [bold]Headers:[/bold] {len(parsed.headers)}")
    if parsed.body_json:
        console.print(f"  [bold]Body keys:[/bold] {len(parsed.body_json)}")
    else:
        console.print(f"  [yellow]No JSON body — only header/global tests will run[/yellow]")
    if crypto_config:
        console.print(f"  [bold]Payload crypto:[/bold] {crypto_config.get('algorithm', 'N/A')}")
    if response_crypto_config:
        console.print(f"  [bold]Response crypto:[/bold] {response_crypto_config.get('algorithm', 'N/A')}")

    console.print("  Running test suite...")
    return run_suite(curl_command, crypto_config, test_cases, settings,
                     response_crypto_config=response_crypto_config)


@cli.command()
def gui():
    """Launch the desktop GUI application."""
    from src.gui import main as gui_main
    gui_main()


@cli.command()
def seed_test_cases():
    """Generate the default test case bank xlsx."""
    from scripts.seed_test_cases import create_test_cases_xlsx
    output_path = Path(__file__).parent.parent / "test_cases" / "default_test_cases.xlsx"
    create_test_cases_xlsx(str(output_path))
    console.print(f"[green]Created:[/green] {output_path}")


@cli.command()
@click.option("--curl", "curl_inline", type=str, help="Inline curl command string")
@click.option("--curl-file", type=click.Path(exists=True, dir_okay=False), help="Path to file containing curl command")
def validate_curl(curl_inline: Optional[str], curl_file: Optional[str]):
    """Dry-run: parse a curl command and display the structured request."""
    curl_command = _read_curl(curl_inline, curl_file)
    if not curl_command:
        console.print("[red]Error:[/red] Provide either --curl or --curl-file")
        sys.exit(1)

    try:
        parsed = parse_curl(curl_command)
    except Exception as e:
        console.print(f"[red]Error parsing curl command:[/red] {e}")
        sys.exit(1)

    table = Table(title="Parsed Request")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Method", parsed.method.value)
    table.add_row("URL", parsed.url)
    table.add_row("Headers", json.dumps(parsed.headers, indent=2) if parsed.headers else "(none)")
    table.add_row("Query Params", json.dumps(parsed.query_params, indent=2) if parsed.query_params else "(none)")
    table.add_row("Body (raw)", parsed.body_raw[:500] or "(none)")
    table.add_row("Body (JSON)", json.dumps(parsed.body_json, indent=2) if parsed.body_json else "(none)")
    table.add_row("Cookies", json.dumps(parsed.cookies, indent=2) if parsed.cookies else "(none)")

    console.print(table)


def _read_curl(inline: Optional[str], file_path: Optional[str]) -> Optional[str]:
    if inline:
        return inline
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return None


def _load_crypto_profile(profile_path: Optional[str], profile_name: str) -> Optional[Dict]:
    if not profile_path:
        return None

    with open(profile_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not config:
        return None

    profiles = config.get("profiles", [config])  # support both list and single profile
    for profile in profiles:
        if profile.get("name") == profile_name:
            return profile

    # Fallback to first profile
    if profiles:
        return profiles[0]

    return None


if __name__ == "__main__":
    cli()
