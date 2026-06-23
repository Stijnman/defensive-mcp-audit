# defensive-mcp-audit

**Defensive Security Audit for AI Agent & MCP (Model Context Protocol) Environments**

Lightweight, local-first, defensive-only tool that detects risky localhost exposure, weak network bindings (`0.0.0.0`), MCP configuration issues, and confused-deputy risks in local AI agent and MCP server setups.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## Why This Exists

The 2025–2026 wave of MCP security research revealed widespread issues with local MCP servers being accidentally exposed (via `0.0.0.0` binding or DNS rebinding attacks), enabling confused-deputy and drive-by attacks on developer machines.

This tool gives you a fast, actionable audit of exactly those risks — with zero offensive capability.

## Features (v0.3.0)

- Dynamic discovery of listening TCP services (`ss` on Linux, `netstat` fallback)
- **Process-aware classification** — MCP-related vs system vs unknown listeners
- **Weighted risk scoring** — Samba on `0.0.0.0` no longer triggers false CRITICAL alerts
- Static MCP config discovery (Claude Desktop, Cursor, VS Code, Grok, `.mcp.json`)
- Framework inventory for installed AI/MCP Python packages
- Plugin architecture with example check in `checks/`
- Multiple output formats:
  - Rich terminal (`text`)
  - `json`
  - `sarif` (GitHub Code Scanning ready)
  - Self-contained `html` report (no CDN dependency)
- Graceful fallback when `typer` / `rich` are not installed
- Designed as both a CLI tool and importable Python package

## Quick Start

```bash
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit
pip install -e ".[cli]"

# Basic run
python3 -m defensive_mcp_audit

# Generate HTML report
python3 -m defensive_mcp_audit --format html -o audit-report.html

# Generate SARIF for CI / GitHub Code Scanning
python3 -m defensive_mcp_audit --format sarif -o results.sarif
```

## Installation (via pip)

```bash
pip install defensive-mcp-audit[cli]

defensive-mcp-audit --help
```

## Use as a Python Module

```python
from defensive_mcp_audit import audit_mcp_environment, generate_sarif, generate_html_report

report = audit_mcp_environment()
print(report["risk_level"], report["risk_score"])

sarif = generate_sarif(report)
html = generate_html_report(report)
```

## GitHub Actions Example (SARIF upload)

See `.github/workflows/defensive-mcp-audit.yml`

## Recommended Hardening (from typical audit output)

1. Bind every MCP / agent HTTP or WebSocket server to `127.0.0.1` only
2. Require authentication tokens on all local endpoints
3. Keep agent frameworks up to date
4. Run high-privilege tools inside containers
5. Apply least-privilege: only expose the tools an agent actually needs

## Project Structure

```
defensive-mcp-audit/
├── defensive_mcp_audit/          # Python package
│   ├── audit.py                    # Core orchestration
│   ├── network.py                  # Listener discovery + classification
│   ├── mcp_config.py               # Static MCP config parsing
│   ├── plugins/                    # Plugin registry
│   └── ...
├── checks/                         # Example/custom defensive checks
├── tests/                          # Unit tests
├── defensive_mcp_audit.py          # Backward-compatible entry point
├── pyproject.toml
├── SKILL.md
└── .github/workflows/
```

## Plugin checks

Add a module under `checks/` with a `run_check(context)` function returning a list of findings.
See `checks/example_port_check.py` for a template.

Disable plugins at runtime:

```bash
defensive-mcp-audit --no-plugins
```

## Roadmap

- [x] Plugin architecture for custom checks (#1)
- [x] Non-invasive MCP manifest / config discovery (#2)
- [ ] Docker / container runtime inspection
- [ ] Historical risk trending dashboard
- [ ] Pre-built GitHub Action (one-click)

## Development

```bash
pip install -e ".[dev]"
python3 -m unittest discover -s tests -v
```

## License

MIT License — see `LICENSE` file.

## Ethics & Scope

Strictly **defensive**.  
Read-only inspection only. No exploitation, no network attacks, no payload generation.

Contributions that stay within the defensive scope are very welcome.

## Acknowledgments

Inspired by real-world MCP security research (2025–2026) around localhost exposure, DNS rebinding, and confused-deputy problems in agentic systems.