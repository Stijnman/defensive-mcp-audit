#!/usr/bin/env python3
"""
Defensive Security Audit Skill for AI Agent / MCP Environments
Focus: Detection of risky localhost exposure, weak bindings, and configuration issues
(Defensive only — no exploit functionality)

Version: 0.2.0-quickwin
"""

import json
import subprocess
import sys
import importlib.util
import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

class BaseAuditPlugin:
    """Base class for custom defensive audit plugins."""
    def audit(self, report: Dict[str, Any], services: List[Dict[str, Any]]) -> None:
        """
        Modify `report` in place (append to report["findings"] and adjust report["risk_score"]).
        `services` contains the list of discovered listening services.
        """
        pass

def load_and_run_plugins(report: Dict[str, Any], services: List[Dict[str, Any]]) -> None:
    """Dynamically load and run any plugins found in the local plugins/ directory."""
    plugins_dir = Path("plugins")
    if not plugins_dir.is_dir():
        return
        
    for py_file in plugins_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        try:
            module_name = f"plugins.{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # To handle circular/duplicate imports from __main__, we check base class names
                    if any(base.__name__ == 'BaseAuditPlugin' for base in obj.__bases__):
                        plugin_instance = obj()
                        plugin_instance.audit(report, services)
        except Exception as e:
            report["findings"].append({
                "id": "PLUGIN_LOAD_ERROR",
                "category": "Plugins",
                "severity": "info",
                "title": f"Failed to load plugin {py_file.name}",
                "value": str(e),
                "note": "A plugin failed to load or execute."
            })

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    typer = None

def get_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat() + "Z"

def discover_listening_services() -> List[Dict[str, Any]]:
    services = []
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return services
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[3]
            process_info = parts[5] if len(parts) > 5 else ""
            if ":" not in local_addr:
                continue
            if local_addr.startswith("["):
                addr_part, port_part = local_addr.rsplit(":", 1)
                address = addr_part
            else:
                address, port_part = local_addr.rsplit(":", 1)
            try:
                port = int(port_part)
            except ValueError:
                continue
            process = ""
            pid = ""
            if "pid=" in process_info:
                try:
                    pid_part = process_info.split("pid=")[1].split(",")[0]
                    pid = pid_part
                    if '"' in process_info:
                        process = process_info.split('"')[1]
                except Exception:
                    pass
            services.append({
                "port": port,
                "address": address,
                "process": process,
                "pid": pid,
                "raw": line.strip()
            })
    except Exception:
        pass
    return services

def is_risky_binding(address: str) -> bool:
    address = address.strip("[]")
    if address in ("0.0.0.0", "::", "*", "0:0:0:0:0:0:0:0"):
        return True
    if address.startswith("::ffff:"):
        return True
    return False

def check_package_version(package_name: str) -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package_name],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "Not installed or error"

def audit_mcp_environment() -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "timestamp": get_timestamp(),
        "audit_type": "defensive_mcp_agent_audit",
        "version": "0.2.0-quickwin",
        "findings": [],
        "risk_score": 0,
        "risk_level": "low",
        "recommendations": [],
        "services_discovered": []
    }

    services = discover_listening_services()
    report["services_discovered"] = services

    exposed_risky = [s for s in services if is_risky_binding(s["address"])]

    for svc in exposed_risky:
        report["risk_score"] += 30

    if exposed_risky:
        report["findings"].append({
            "id": "EXPOSED_NON_LOCALHOST",
            "category": "Network Exposure",
            "severity": "high",
            "title": "Services listening on non-localhost interfaces",
            "value": [f"{s['address']}:{s['port']} ({s.get('process') or 'unknown'})" for s in exposed_risky],
            "note": "These services may be reachable from other machines or via DNS rebinding attacks. Bind MCP/agent services to 127.0.0.1 only."
        })
        report["recommendations"].extend([
            "Change all MCP / agent servers to bind explicitly to 127.0.0.1 (or ::1)",
            "Add firewall rules to drop external traffic to these ports",
            "Enable authentication on every exposed endpoint"
        ])

    if services:
        report["findings"].append({
            "id": "LISTENING_SERVICES",
            "category": "Network Exposure",
            "severity": "info",
            "title": f"Discovered {len(services)} listening TCP services",
            "value": [f"{s['address']}:{s['port']}" for s in services[:10]],
            "note": "Review each service for necessity and apply least-privilege binding + auth."
        })

    frameworks = ["autogen", "crewai", "langchain", "semantic-kernel", "openai"]
    for fw in frameworks:
        ver = check_package_version(fw)
        report["findings"].append({
            "id": f"FRAMEWORK_VERSION_{fw.upper().replace('-', '_')}",
            "category": "Dependencies",
            "severity": "info",
            "title": f"{fw} version",
            "value": ver,
            "note": "Review against latest secure releases."
        })

    if exposed_risky or any(s["port"] in (8000, 8080, 9000, 5000, 6277) for s in services):
        report["findings"].append({
            "id": "CONFUSED_DEPUTY_RISK",
            "category": "MCP / Agent Trust Boundary",
            "severity": "high" if exposed_risky else "medium",
            "title": "Potential confused deputy / localhost trust boundary risk",
            "value": "Browsing/web-enabled agents + local MCP services detected",
            "note": "A compromised or tricked agent (or malicious webpage via DNS rebinding) could reach local MCP endpoints. Enforce auth + input validation."
        })
        report["recommendations"].extend([
            "Require authentication tokens on all MCP/WebSocket/HTTP endpoints",
            "Implement strict input validation and sandboxing for web-facing agent tools"
        ])

    report["recommendations"].extend([
        "Keep all AI agent frameworks and MCP servers up to date",
        "Regularly review Microsoft, Anthropic, CrewAI, and OWASP MCP security guidance",
        "Run agents and MCP servers in isolated containers or VMs when possible",
        "Disable unnecessary local services and MCP tools when not actively needed",
        "Apply least-privilege principles: only expose the exact tools an agent requires"
    ])

    load_and_run_plugins(report, services)

    score = report["risk_score"]
    if score >= 60:
        report["risk_level"] = "critical"
    elif score >= 30:
        report["risk_level"] = "high"
    elif score >= 10:
        report["risk_level"] = "medium"
    else:
        report["risk_level"] = "low"

    return report

def generate_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "defensive-mcp-audit",
                    "version": report.get("version", "0.2.0"),
                    "informationUri": "https://github.com/your-org/defensive-mcp-audit"
                }
            },
            "results": []
        }]
    }
    for finding in report.get("findings", []):
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(finding.get("severity", "info"), "note")
        result = {
            "ruleId": finding.get("id", "UNKNOWN"),
            "level": level,
            "message": {"text": f"{finding.get('title', '')}: {finding.get('note', '')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "local-environment"}, "region": {"startLine": 1}}}]
        }
        sarif["runs"][0]["results"].append(result)
    return sarif

def generate_html_report(report: Dict[str, Any]) -> str:
    risk_colors = {
        "critical": "bg-red-600 text-white",
        "high": "bg-orange-500 text-white",
        "medium": "bg-yellow-500 text-black",
        "low": "bg-green-500 text-white",
        "info": "bg-blue-500 text-white"
    }
    risk_class = risk_colors.get(report.get("risk_level", "low"), "bg-gray-500")

    findings_html = ""
    for f in report.get("findings", []):
        sev = f.get("severity", "info")
        sev_color = {"high": "text-red-600 font-bold", "medium": "text-orange-600 font-semibold", "low": "text-yellow-600", "info": "text-blue-600"}.get(sev, "text-gray-600")
        val = f.get('value')
        if isinstance(val, (list, dict)):
            val_str = json.dumps(val, indent=2)
        else:
            val_str = str(val)
        findings_html += f"""
        <div class="border-l-4 pl-4 mb-4 {'border-red-500' if sev in ('high','critical') else 'border-gray-300'}">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 text-xs rounded {sev_color}">{sev.upper()}</span>
                <span class="font-mono text-sm text-gray-500">{f.get('id')}</span>
            </div>
            <div class="font-semibold mt-1">{f.get('title')}</div>
            <div class="text-sm text-gray-700 mt-1">{f.get('note')}</div>
            <div class="mt-1 text-xs bg-gray-100 p-2 rounded font-mono overflow-x-auto text-black">{val_str}</div>
        </div>
        """

    services_html = ""
    for s in report.get("services_discovered", [])[:15]:
        risky = is_risky_binding(s.get("address", ""))
        services_html += f"""
        <tr class="{'bg-red-50' if risky else ''}">
            <td class="px-3 py-1 font-mono">{s.get('address')}:{s.get('port')}</td>
            <td class="px-3 py-1">{s.get('process') or '-'}</td>
            <td class="px-3 py-1 text-xs">{s.get('pid') or '-'}</td>
            <td class="px-3 py-1">{'<span class="text-red-600 font-bold">RISKY</span>' if risky else '<span class="text-green-600">localhost</span>'}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defensive MCP Audit Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-zinc-950 text-zinc-200">
<div class="max-w-5xl mx-auto p-8">
    <div class="flex justify-between items-start mb-8">
        <div>
            <h1 class="text-4xl font-bold tracking-tight">Defensive MCP / AI Agent Audit</h1>
            <p class="text-zinc-400 mt-1">Local environment security posture • {report.get('timestamp')}</p>
        </div>
        <div class="text-right">
            <div class="inline-flex items-center gap-2 px-4 py-1 rounded-full {risk_class}">
                <span class="font-mono text-sm">RISK</span>
                <span class="font-bold text-xl">{report.get('risk_level', 'low').upper()}</span>
            </div>
            <div class="text-xs text-zinc-500 mt-1">Score: {report.get('risk_score')}</div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div class="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <h2 class="font-semibold mb-4 flex items-center gap-2">Key Findings</h2>
            {findings_html or '<p class="text-zinc-400">No significant findings.</p>'}
        </div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
            <h2 class="font-semibold mb-4">Recommendations</h2>
            <ul class="space-y-2 text-sm">
                {''.join(f'<li class="flex gap-2"><span class="text-emerald-400">→</span> {r}</li>' for r in report.get('recommendations', []))}
            </ul>
        </div>
    </div>

    <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 mb-8">
        <h2 class="font-semibold mb-4">Discovered Listening Services ({len(report.get('services_discovered', []))})</h2>
        <table class="w-full text-sm">
            <thead><tr class="text-left text-zinc-400 border-b border-zinc-800">
                <th class="py-2 px-3">Address:Port</th>
                <th class="py-2 px-3">Process</th>
                <th class="py-2 px-3">PID</th>
                <th class="py-2 px-3">Binding</th>
            </tr></thead>
            <tbody class="font-mono text-xs">{services_html or '<tr><td colspan="4" class="px-3 py-2 text-zinc-400">No listening services detected.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="text-xs text-zinc-500 text-center">
        Generated by defensive-mcp-audit v{report.get('version')} • Defensive only • {report.get('timestamp')}
    </div>
</div>
</body>
</html>"""
    return html

def print_text_report(report: Dict[str, Any], console: Optional[Any] = None) -> None:
    if RICH_AVAILABLE and console:
        console.rule("[bold]Defensive MCP / AI Agent Security Audit[/bold]")
        console.print(f"Timestamp: {report['timestamp']}  |  Risk: [bold]{report['risk_level'].upper()}[/bold] ({report['risk_score']})")
        table = Table(title="Findings", show_lines=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="magenta")
        table.add_column("Title")
        table.add_column("Note", style="dim")
        for f in report.get("findings", []):
            table.add_row(f.get("id", ""), f.get("severity", ""), f.get("title", ""), str(f.get("note", ""))[:80])
        console.print(table)
        console.print("\n[bold]Recommendations:[/bold]")
        for r in report.get("recommendations", []):
            console.print(f"  • {r}")
    else:
        print("=== Defensive MCP / AI Agent Security Audit ===")
        print(json.dumps(report, indent=2))

def _run_cli():
    import typer as _typer
    from pathlib import Path as _Path
    app = _typer.Typer(help="Defensive MCP / AI Agent Security Audit")

    @app.command()
    def audit(
        output: Optional[_Path] = _typer.Option(None, "--output", "-o", help="Output file path"),
        fmt: str = _typer.Option("text", "--format", "-f", help="text | json | sarif | html"),
        verbose: bool = _typer.Option(False, "--verbose", "-v")
    ):
        if not RICH_AVAILABLE:
            print("[warning] rich/typer not installed. Falling back to basic output.", file=sys.stderr)
        console = Console() if RICH_AVAILABLE else None
        report = audit_mcp_environment()
        if output and not fmt:
            ext = output.suffix.lower()
            fmt = {"json": "json", "sarif": "sarif", "html": "html"}.get(ext, "text")
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
            if RICH_AVAILABLE and console:
                console.print(f"\n[green]Report saved to[/green] {output}")
            else:
                print(f"\nReport saved to {output}")
        elif content and verbose:
            print(content)
    app()

if __name__ == "__main__":
    if typer is not None:
        _run_cli()
    else:
        report = audit_mcp_environment()
        print_text_report(report)
        Path("defensive_audit_report.json").write_text(json.dumps(report, indent=2))
        print("\nReport also saved to defensive_audit_report.json (JSON)")