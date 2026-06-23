---
name: defensive-mcp-audit
description: >
  Run a defensive, read-only security audit of the local machine for MCP and AI agent risks:
  risky network bindings (0.0.0.0), MCP server configuration issues, confused-deputy exposure,
  and installed agent framework inventory. Outputs text, JSON, SARIF, or HTML reports.
metadata:
  short-description: Defensive MCP/agent localhost security audit
  argument-hint: "[--format json|sarif|html] [--output path]"
  when-to-use: >
    "audit mcp", "check localhost exposure", "mcp security", "confused deputy",
    "scan listening ports", "defensive-mcp-audit", before enabling new MCP servers
---

# defensive-mcp-audit

Defensive-only audit for local MCP and AI agent environments. Read-only. No exploitation.

## When to use

- Before enabling a new MCP server or agent gateway
- After installing Hermes, Claude Desktop MCP, Cursor MCP, or Grok MCP integrations
- In CI weekly jobs on developer machines
- When investigating DNS rebinding / localhost trust-boundary concerns

## Quick commands

```bash
# From repo clone
python3 -m defensive_mcp_audit

# Installed CLI
pip install defensive-mcp-audit[cli]
defensive-mcp-audit --format html -o audit-report.html
defensive-mcp-audit --format sarif -o results.sarif
defensive-mcp-audit --format json -o report.json
```

## Python API

```python
from defensive_mcp_audit import audit_mcp_environment, generate_sarif, generate_html_report

report = audit_mcp_environment()
print(report["risk_level"], report["risk_score"])
```

## What it checks

1. Listening TCP services (`ss` on Linux, `netstat` fallback)
2. MCP-related vs system vs unknown process classification
3. Weighted risk scoring (Samba ≠ MCP server)
4. Static MCP config discovery (Claude, Cursor, VS Code, Grok, `.mcp.json`)
5. Installed AI framework package inventory
6. Optional plugin checks in `checks/` (see `checks/example_port_check.py`)

## Interpreting results

| Finding ID | Meaning |
|------------|---------|
| `MCP_EXPOSED_NON_LOCALHOST` | MCP-related service on 0.0.0.0 — fix immediately |
| `SYSTEM_EXPOSED_LISTENER` | OS service (e.g. Samba) — informational |
| `MCP_CONFIG_RISK` | Risky patterns in MCP client config |
| `CONFUSED_DEPUTY_RISK` | Local MCP surface reachable by agents/browsers |

## Ethics

Strictly defensive. Never generate exploits, payloads, or offensive guidance.