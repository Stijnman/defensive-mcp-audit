<p align="center">
  <img src="assets/logo.svg" alt="defensive-mcp-audit" width="96">
</p>

<h1 align="center">defensive-mcp-audit</h1>

<p align="center">
  <strong>Defensive security audit for AI Agent & MCP environments</strong><br>
  Detect risky localhost exposure, weak bindings, and confused-deputy risks — with zero offensive capability.
</p>

<p align="center">
  <a href="https://github.com/Stijnman/defensive-mcp-audit/actions/workflows/defensive-mcp-audit.yml"><img src="https://github.com/Stijnman/defensive-mcp-audit/actions/workflows/defensive-mcp-audit.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Stijnman/defensive-mcp-audit/releases/latest"><img src="https://img.shields.io/github/v/release/Stijnman/defensive-mcp-audit?label=release" alt="Release"></a>
  <a href="https://pypi.org/project/defensive-mcp-audit/"><img src="https://img.shields.io/pypi/v/defensive-mcp-audit?label=pypi" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
</p>

<p align="center">
  <img src="assets/social-preview.svg" alt="defensive-mcp-audit preview" width="720">
</p>

---

## Why this exists

MCP security research (2025–2026) showed that local MCP servers are often accidentally exposed via `0.0.0.0` bindings or reachable through DNS rebinding — enabling confused-deputy and drive-by attacks on developer machines.

This tool gives you a **fast, actionable, defensive-only** audit of those risks on your own machine.

## Features

| Capability | Description |
| --- | --- |
| Listener discovery | `ss` on Linux, `netstat` fallback elsewhere |
| Smart classification | MCP-related vs system vs unknown processes |
| Weighted scoring | Samba ≠ MCP — fewer false CRITICAL alerts |
| MCP config scan | Claude, Cursor, VS Code, Grok, `.mcp.json` |
| Docker inspection | Read-only `docker ps` port publish analysis |
| Output formats | Terminal, JSON, SARIF, self-contained HTML |
| CI-ready | GitHub Action + weekly SARIF workflow included |
| Extensible | Plugin checks in `checks/` |

## Quick start

```bash
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit
pip install -e ".[cli]"

python -m defensive_mcp_audit
python -m defensive_mcp_audit --format html -o audit-report.html
python -m defensive_mcp_audit --format sarif -o results.sarif
```

All command-line options work with the base installation; the optional `cli` extra adds Rich terminal formatting. JSON, SARIF, and HTML go to stdout unless `--output` is given, so `python -m defensive_mcp_audit --format json > report.json` works without `--verbose`. Text reports can also be saved with `--output report.txt`. Save notices go to stderr, and no extra JSON file is created implicitly. Invalid formats fail before inspection begins.

### Example output

```text
Risk: HIGH (65)

Findings:
  [medium] UNKNOWN_EXPOSED_LISTENER — Unclassified 0.0.0.0 bindings
  [info]   MCP_LOCALHOST_OK         — Ollama on 127.0.0.1:11434
  [info]   SYSTEM_EXPOSED_LISTENER  — smbd on 0.0.0.0:445 (informational)
```

## Install

```bash
pip install defensive-mcp-audit[cli]

# Or from GitHub
pip install "git+https://github.com/Stijnman/defensive-mcp-audit@v0.3.2#egg=defensive-mcp-audit[cli]"
```

## Python API

```python
from defensive_mcp_audit import audit_mcp_environment, generate_sarif, generate_html_report

report = audit_mcp_environment()
print(report["risk_level"], report["risk_score"])
```

## GitHub Action (one-click CI)

Add to any workflow:

```yaml
- uses: Stijnman/defensive-mcp-audit/action@v0.3.2
  with:
    upload-sarif: "true"
```

Or run the full workflow — see [`.github/workflows/defensive-mcp-audit.yml`](.github/workflows/defensive-mcp-audit.yml).

## Finding reference

| ID | Severity | Meaning |
| --- | --- | --- |
| `MCP_EXPOSED_NON_LOCALHOST` | high | MCP-related service on a wildcard or explicit non-loopback IP — review and restrict its binding |
| `UNKNOWN_EXPOSED_LISTENER` | medium | Unclassified non-loopback listener — review |
| `SYSTEM_EXPOSED_LISTENER` | info | OS service (e.g. Samba) — noted, low MCP impact |
| `MCP_CONFIG_RISK` | medium | Risky patterns in MCP client config |
| `CONFUSED_DEPUTY_RISK` | medium/high | Local MCP surface + agent/browser trust boundary |

## Project structure

```text
defensive-mcp-audit/
├── defensive_mcp_audit/     # Core package
├── checks/                  # Plugin checks
├── action/                  # Composite GitHub Action
├── tests/
├── SKILL.md                 # Agent skill integration
└── .github/
```

## Development

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Roadmap

- [x] Plugin architecture (#1)
- [x] MCP config discovery (#2)
- [x] Composite GitHub Action
- [x] PyPI trusted publishing workflow
- [x] Docker / container runtime inspection
- [ ] Historical risk trending

## Ethics

Strictly **defensive**. Read-only inspection. No exploitation, payloads, or network attacks.

### What a finding proves

Listener checks identify wildcard and explicit non-loopback IP bindings; they do not establish Internet reachability or test firewall rules. Service classification is heuristic: a common port or process name is not proof that a service speaks MCP. Config inspection does not execute server commands, contact endpoints, verify OAuth flows, or establish whether authentication is actually enforced. Treat missing authentication hints as a review prompt, not a confirmed vulnerability, and do not publish reports containing private paths or environment details without review.

For local HTTP servers, localhost binding is only one layer. The [MCP HTTP transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#security--endpoint) also requires Origin validation to mitigate DNS rebinding and recommends appropriate authentication. Stdio uses a different trust boundary; HTTP endpoint authentication checks do not apply to a local stdio subprocess in the same way.

## License

MIT — see [LICENSE](LICENSE).

## Flagship integration

This project remains independently usable and is not deprecated. Its capabilities are also consumed by [AetherOS](https://github.com/Stijnman/AetherOS) and [AegisAI](https://github.com/Stijnman/AegisAI), where they are integrated with complementary repositories behind shared platform contracts. This repository remains the source of truth for its component-specific implementation.
