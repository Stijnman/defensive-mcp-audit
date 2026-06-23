# Contributing to defensive-mcp-audit

Thank you for helping make local MCP and AI agent environments safer.

This project is strictly **defensive**:

- Read-only inspection only
- No exploitation, attack simulation, or offensive tooling
- Detection, hardening recommendations, and developer safety

## Quick start

```bash
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m unittest discover -s tests -v
python -m defensive_mcp_audit
```

## Adding a defensive check (plugin)

1. Create `checks/your_check.py`
2. Implement `run_check(context: dict) -> list[dict]`
3. Return findings with `id`, `category`, `severity`, `title`, `value`, `note`
4. See `checks/example_port_check.py` for a template

Plugins load automatically unless `--no-plugins` is passed.

## Pull requests

- Branch from `main`
- Keep changes focused
- Update tests and `CHANGELOG.md` for user-facing changes
- Use the PR template

## Code style

- Core package stays dependency-minimal
- Prefer clear heuristics over invasive scanning
- Log discovery failures to stderr instead of silent `except: pass`
- All new findings must be actionable and documented

## Security

Report tool vulnerabilities via [GitHub Security Advisories](https://github.com/Stijnman/defensive-mcp-audit/security/advisories/new). See `SECURITY.md`.

## License

Contributions are licensed under the MIT License.