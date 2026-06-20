# Contributing to defensive-mcp-audit

Thank you for your interest in contributing to **defensive-mcp-audit**!

This project is strictly **defensive**. All contributions must respect this scope:
- Read-only inspection only
- No exploitation, attack simulation, or offensive tooling
- Focus on detection, hardening recommendations, and developer safety

## How to Contribute

1. **Fork** the repository and create your branch from `main`.
2. Make your changes.
3. Ensure the tool still runs cleanly (`python3 defensive_mcp_audit.py`).
4. Add or update tests if applicable.
5. Submit a **Pull Request**.

## Development Setup

```bash
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit
python3 -m venv .venv
source .venv/bin/activate
pip install "typer[all]" rich
```

## Code Style

- Keep the core lightweight and dependency-minimal.
- New checks should be easy to add (see upcoming plugin architecture in v0.3).
- All findings must include clear `id`, `severity`, `title`, and `note`.
- Prefer defensive heuristics over active scanning.

## Reporting Issues

Please use the issue templates and label them appropriately:
- `bug`
- `enhancement`
- `good first issue`
- `documentation`

Security-related reports should be handled responsibly (we welcome private disclosure for any potential issues in the tool itself).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for helping make local AI agent and MCP environments safer!