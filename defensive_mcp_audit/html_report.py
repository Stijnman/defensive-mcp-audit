"""Self-contained HTML report generation (no external CDN)."""

from __future__ import annotations

import html
import json
from typing import Any, Dict

RISK_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
}


def _render_findings(findings: list[Dict[str, Any]]) -> str:
    blocks = []
    for finding in findings:
        severity = finding.get("severity", "info")
        value = finding.get("value")
        if isinstance(value, (list, dict)):
            value_text = html.escape(json.dumps(value, indent=2))
        else:
            value_text = html.escape(str(value))
        border = "#dc2626" if severity in {"high", "critical"} else "#3f3f46"
        blocks.append(
            f"""
            <div class="finding" style="border-left-color:{border}">
              <div class="meta"><span class="sev sev-{severity}">{severity.upper()}</span>
                <span class="fid">{html.escape(finding.get('id', ''))}</span></div>
              <h3>{html.escape(finding.get('title', ''))}</h3>
              <p>{html.escape(finding.get('note', ''))}</p>
              <pre>{value_text}</pre>
            </div>
            """
        )
    return "".join(blocks) or "<p class='muted'>No findings recorded.</p>"


def _render_services(services: list[Dict[str, Any]]) -> str:
    rows = []
    for service in services[:20]:
        risky = service.get("risky_binding")
        label = "RISKY" if risky else "localhost"
        row_class = "risky" if risky and service.get("classification") == "mcp_related" else ""
        rows.append(
            "<tr class='{cls}'>"
            "<td>{addr}:{port}</td>"
            "<td>{process}</td>"
            "<td>{classification}</td>"
            "<td>{label}</td>"
            "</tr>".format(
                cls=row_class,
                addr=html.escape(str(service.get("address", ""))),
                port=html.escape(str(service.get("port", ""))),
                process=html.escape(service.get("process") or "-"),
                classification=html.escape(service.get("classification", "unknown")),
                label=label,
            )
        )
    return "".join(rows) or "<tr><td colspan='4' class='muted'>No listeners detected.</td></tr>"


def generate_html_report(report: Dict[str, Any]) -> str:
    risk_level = report.get("risk_level", "low")
    risk_color = RISK_COLORS.get(risk_level, "#71717a")
    recommendations = report.get("recommendations", [])
    rec_html = "".join(f"<li>{html.escape(item)}</li>" for item in recommendations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Defensive MCP Audit Report</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:#09090b; color:#e4e4e7; }}
    .wrap {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
    .header {{ display:flex; justify-content:space-between; gap:1rem; align-items:flex-start; margin-bottom:2rem; }}
    .badge {{ background:{risk_color}; color:#fff; padding:.5rem 1rem; border-radius:999px; font-weight:700; }}
    .grid {{ display:grid; grid-template-columns: 2fr 1fr; gap:1rem; }}
    .card {{ background:#18181b; border:1px solid #27272a; border-radius:1rem; padding:1.25rem; margin-bottom:1rem; }}
    .finding {{ border-left:4px solid #3f3f46; padding-left:1rem; margin-bottom:1rem; }}
    .meta {{ display:flex; gap:.5rem; align-items:center; margin-bottom:.25rem; }}
    .sev {{ font-size:.7rem; padding:.15rem .45rem; border-radius:.35rem; font-weight:700; }}
    .sev-high, .sev-critical {{ background:#7f1d1d; color:#fecaca; }}
    .sev-medium {{ background:#78350f; color:#fde68a; }}
    .sev-low, .sev-info {{ background:#1e3a8a; color:#bfdbfe; }}
    .fid {{ font-family: monospace; color:#a1a1aa; font-size:.8rem; }}
    pre {{ background:#09090b; border:1px solid #27272a; padding:.75rem; overflow:auto; font-size:.75rem; }}
    table {{ width:100%; border-collapse: collapse; font-size:.85rem; }}
    th, td {{ text-align:left; padding:.5rem; border-bottom:1px solid #27272a; }}
    tr.risky {{ background:#451a1a; }}
    .muted {{ color:#a1a1aa; }}
    h1 {{ margin:0 0 .25rem; }}
    h2, h3 {{ margin-top:0; }}
    ul {{ padding-left: 1.1rem; }}
    @media (max-width: 800px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <h1>Defensive MCP / AI Agent Audit</h1>
        <p class="muted">Local environment security posture • {html.escape(report.get('timestamp', ''))}</p>
      </div>
      <div style="text-align:right">
        <div class="badge">RISK {html.escape(risk_level.upper())}</div>
        <div class="muted" style="margin-top:.35rem">Score: {report.get('risk_score', 0)}</div>
      </div>
    </div>
    <div class="grid">
      <div class="card">
        <h2>Key Findings</h2>
        {_render_findings(report.get('findings', []))}
      </div>
      <div class="card">
        <h2>Recommendations</h2>
        <ul>{rec_html}</ul>
      </div>
    </div>
    <div class="card">
      <h2>Discovered Listening Services ({len(report.get('services_discovered', []))})</h2>
      <table>
        <thead><tr><th>Address:Port</th><th>Process</th><th>Class</th><th>Binding</th></tr></thead>
        <tbody>{_render_services(report.get('services_discovered', []))}</tbody>
      </table>
    </div>
    <p class="muted" style="text-align:center">Generated by defensive-mcp-audit v{html.escape(report.get('version', ''))} • Defensive only</p>
  </div>
</body>
</html>"""