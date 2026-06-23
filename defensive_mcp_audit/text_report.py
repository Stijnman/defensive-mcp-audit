"""Terminal report rendering."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

try:
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def print_text_report(report: Dict[str, Any], console: Optional[Any] = None) -> None:
    if RICH_AVAILABLE and console is not None:
        console.rule("[bold]Defensive MCP / AI Agent Security Audit[/bold]")
        console.print(
            f"Timestamp: {report['timestamp']}  |  Risk: "
            f"[bold]{report['risk_level'].upper()}[/bold] ({report['risk_score']})"
        )
        table = Table(title="Findings", show_lines=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="magenta")
        table.add_column("Title")
        table.add_column("Note", style="dim")
        for finding in report.get("findings", []):
            if finding.get("severity") == "info" and finding.get("id") not in {
                "MCP_EXPOSED_NON_LOCALHOST",
                "CONFUSED_DEPUTY_RISK",
                "MCP_CONFIG_RISK",
            }:
                continue
            table.add_row(
                finding.get("id", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                str(finding.get("note", ""))[:100],
            )
        console.print(table)
        console.print("\n[bold]Recommendations:[/bold]")
        for recommendation in report.get("recommendations", []):
            console.print(f"  • {recommendation}")
    else:
        print("=== Defensive MCP / AI Agent Security Audit ===")
        print(json.dumps(report, indent=2))