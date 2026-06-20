# defensive-mcp-audit

**Defensive Security Audit for AI Agent & MCP (Model Context Protocol) Environments**

Lightweight, local-first, defensive-only tool that detects risky localhost exposure, weak network bindings (`0.0.0.0`), and confused-deputy risks in local AI agent and MCP server setups.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## Why This Exists

The 2025–2026 wave of MCP security research revealed widespread issues with local MCP servers being accidentally exposed (via `0.0.0.0` binding or DNS rebinding attacks), enabling confused-deputy and drive-by attacks on developer machines.

### 3. Review Findings
The audit outputs a structured report highlighting network bindings, vulnerable frameworks, and the potential for a confused deputy attack.
Each finding includes an actionable recommendation.

## Custom Plugins
You can inject your own custom security checks dynamically without modifying the core script.

1. Create a `plugins/` directory next to `defensive_mcp_audit.py`.
2. Add a Python file (e.g., `my_check.py`) that implements a subclass of `BaseAuditPlugin`.

**Example: `plugins/docker_check.py`**
```python
from defensive_mcp_audit import BaseAuditPlugin
from typing import Dict, Any, List

class DockerSocketExposurePlugin(BaseAuditPlugin):
    def audit(self, report: Dict[str, Any], services: List[Dict[str, Any]]) -> None:
        for svc in services:
            if svc["port"] in {2375, 2376} and svc["address"] not in ("127.0.0.1", "::1"):
                report["risk_score"] += 50
                report["findings"].append({
                    "id": "DOCKER_SOCKET_EXPOSED",
                    "category": "Plugins",
                    "severity": "critical",
                    "title": "Exposed Docker API detected",
                    "value": f"{svc['address']}:{svc['port']}",
                    "note": "Docker API is exposed on a non-localhost interface."
                })
```
All custom plugins are automatically discovered and executed before the final risk score is computed.

## Features (v0.2.0)

- Dynamic discovery of listening TCP services via `ss`
- Automatic flagging of risky non-localhost bindings
- Framework version checks (AutoGen, CrewAI, LangChain, etc.)
- Enhanced confused-deputy / localhost trust-boundary warnings
- Multiple output formats:
  - Rich terminal (`text`)
  - `json`
  - `sarif` (GitHub Code Scanning ready)
  - Beautiful self-contained `html` report
- Graceful fallback when `typer` / `rich` are not installed
- Designed to be both a CLI tool and an importable Python skill/module

## Quick Start

```bash
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit

# Basic run
python3 defensive_mcp_audit.py

# Generate beautiful HTML report
python3 defensive_mcp_audit.py --format html -o audit-report.html

# Generate SARIF for CI / GitHub Code Scanning
python3 defensive_mcp_audit.py --format sarif -o results.sarif

# With rich CLI (recommended)
pip install "typer[all]" rich
python3 defensive_mcp_audit.py --verbose
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

## Visual Assets

### Repository Header / Social Preview

**Dark theme (recommended):**

![defensive-mcp-audit Header](assets/defensive-mcp-audit-header-dark.jpg)

**Light theme variant:**

![defensive-mcp-audit Header Light](assets/defensive-mcp-audit-header-light.jpg)

### Logo / Icon

![defensive-mcp-audit Logo](assets/defensive-mcp-audit-logo.png)

### Demo / Usage Thumbnail

![Demo Thumbnail](assets/defensive-mcp-audit-demo-thumb.jpg)

> **Note:** Download the generated images from the `imagine_images` folder and place them in an `assets/` directory at the root of the repository.

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
├── defensive_mcp_audit.py          # Main CLI + library
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── SKILL.md                        # For local AI agent skill ecosystems
├── assets/                         # Visual assets (headers, logo, thumbnails)
├── templates/
│   └── html_report.html.j2
└── .github/
    └── workflows/
        └── defensive-mcp-audit.yml
```

## Roadmap

- Plugin architecture for custom checks (see issues #1 and #2)
- Deeper (non-invasive) MCP manifest / tool discovery
- Docker / container runtime inspection
- Historical risk trending dashboard
- Pre-built GitHub Action (one-click)

## License

MIT License — see `LICENSE` file.

## Ethics & Scope

Strictly **defensive**.  
Read-only inspection only. No exploitation, no network attacks, no payload generation.

Contributions that stay within the defensive scope are very welcome.

## Acknowledgments

Inspired by real-world MCP security research (2025–2026) around localhost exposure, DNS rebinding, and confused-deputy problems in agentic systems.