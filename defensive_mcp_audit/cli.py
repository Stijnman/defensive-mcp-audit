"""CLI entry point."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from defensive_mcp_audit.audit import audit_mcp_environment
from defensive_mcp_audit.html_report import generate_html_report
from defensive_mcp_audit.sarif import generate_sarif
from defensive_mcp_audit.text_report import RICH_AVAILABLE, print_text_report

try:
    import typer
    from rich.console import Console
except ImportError:
    typer = None
    Console = None


def _write_report(
    report: dict,
    *,
    output: Optional[Path],
    fmt: str,
    verbose: bool,
    console: Optional[object],
) -> None:
    if fmt == "json":
        content = json.dumps(report, indent=2)
    elif fmt == "sarif":
        content = json.dumps(generate_sarif(report), indent=2)
    elif fmt == "html":
        content = generate_html_report(report)
    else:
        print_text_report(report, console)
        content = None

    if content and output:
        output.write_text(content, encoding="utf-8")
        if RICH_AVAILABLE and console is not None:
            console.print(f"\n[green]Report saved to[/green] {output}")
        else:
            print(f"\nReport saved to {output}")
    elif content and verbose:
        print(content)


def run_cli() -> None:
    if typer is None:
        report = audit_mcp_environment()
        print_text_report(report)
        Path("defensive_audit_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("\nReport also saved to defensive_audit_report.json (JSON)")
        return

    app = typer.Typer(help="Defensive MCP / AI Agent Security Audit")

    @app.callback(invoke_without_command=True)
    def main(
        output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
        fmt: str = typer.Option("text", "--format", "-f", help="text | json | sarif | html"),
        verbose: bool = typer.Option(False, "--verbose", "-v"),
        no_plugins: bool = typer.Option(False, "--no-plugins", help="Disable plugin checks"),
    ) -> None:
        if not RICH_AVAILABLE:
            print(
                "[warning] rich/typer not installed. Falling back to basic output.",
                file=sys.stderr,
            )
        console = Console() if RICH_AVAILABLE else None
        report = audit_mcp_environment(enable_plugins=not no_plugins)
        if output and fmt == "text":
            ext = output.suffix.lower()
            fmt = {".json": "json", ".sarif": "sarif", ".html": "html"}.get(ext, fmt)
        _write_report(report, output=output, fmt=fmt, verbose=verbose, console=console)

    app()


if __name__ == "__main__":
    run_cli()