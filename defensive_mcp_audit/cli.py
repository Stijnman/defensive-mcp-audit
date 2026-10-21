"""CLI entry point with dependency-free argument handling."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from defensive_mcp_audit.audit import audit_mcp_environment
from defensive_mcp_audit.constants import VERSION
from defensive_mcp_audit.html_report import generate_html_report
from defensive_mcp_audit.sarif import generate_sarif
from defensive_mcp_audit.text_report import RICH_AVAILABLE, print_text_report

try:
    from rich.console import Console
except ImportError:
    Console = None


def _write_report(
    report: dict,
    *,
    output: Optional[Path],
    fmt: str,
    verbose: bool,
    console: Optional[object],
) -> None:
    """Write exactly one report to the selected file or stdout.

    ``verbose`` is retained for compatibility; machine formats no longer need it
    to be emitted. Save notices go to stderr so stdout remains machine-readable.
    """
    if fmt == "json":
        content = json.dumps(report, indent=2)
    elif fmt == "sarif":
        content = json.dumps(generate_sarif(report), indent=2)
    elif fmt == "html":
        content = generate_html_report(report)
    elif fmt == "text":
        if output is None:
            print_text_report(report, console)
            return
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            print_text_report(report)
        content = stream.getvalue()
    else:
        raise ValueError(f"Unsupported output format: {fmt}")

    content = content.rstrip("\n") + "\n"
    if output is not None:
        output.write_text(content, encoding="utf-8")
        print(f"Report saved to {output}", file=sys.stderr)
    else:
        sys.stdout.write(content)


def run_cli(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Defensive MCP / AI Agent Security Audit")
    parser.add_argument("--output", "-o", type=Path, help="Output file path (default: stdout)")
    parser.add_argument(
        "--format", "-f", dest="fmt", choices=("text", "json", "sarif", "html"),
        default="text", help="Report format (default: text)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Retained for compatibility")
    parser.add_argument("--no-plugins", action="store_true", help="Disable plugin checks")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    fmt = args.fmt
    # Preserve output-extension inference when no non-text format is selected.
    if args.output is not None and fmt == "text":
        fmt = {".json": "json", ".sarif": "sarif", ".html": "html"}.get(
            args.output.suffix.lower(), fmt,
        )
    console = Console() if RICH_AVAILABLE and Console is not None else None
    report = audit_mcp_environment(enable_plugins=not args.no_plugins)
    try:
        _write_report(
            report, output=args.output, fmt=fmt, verbose=args.verbose, console=console,
        )
    except OSError as error:
        parser.error(f"cannot write report: {error}")


if __name__ == "__main__":
    run_cli()
