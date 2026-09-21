# Contributing to defensive-mcp-audit

This Python package inspects local listeners, MCP configuration and Docker port
bindings, then produces text, JSON, SARIF or HTML reports. Keep new checks
read-only and avoid collecting credentials or executing commands from MCP config.

## Development setup

```sh
git clone https://github.com/Stijnman/defensive-mcp-audit.git
cd defensive-mcp-audit
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m unittest discover -s tests -v
```

On Windows, activate with `.venv\Scripts\activate`. The unit tests use Python's
standard-library unittest framework. CI also installs pytest and runs the same
suite on Python 3.10, 3.11 and 3.12. Optional CLI dependencies enable formatted
terminal output and command-line options.

## Making changes

Create a feature branch and add regression tests for changed behavior. Place
listener fixtures in `tests/fixtures/`; use temporary files and mocks for config,
Docker and subprocess tests. Never commit real MCP configuration or tokens.

The implementation lives in `defensive_mcp_audit/`: `network.py` classifies
listeners, `mcp_config.py` discovers server configuration, `docker_runtime.py`
inspects published ports, and `audit.py` combines findings. Report generators
must escape untrusted content and avoid leaking credentials.

Run the full suite before opening a pull request. Describe the bug or behavior,
the affected modules, and the exact commands/results used to validate it.
The repository's existing tests do not establish complete security coverage.

## Reports and feature requests

Use https://github.com/Stijnman/defensive-mcp-audit/issues for non-sensitive bugs
and proposals. Include the Python version, operating system, command, and a
redacted minimal example. Follow SECURITY.md for sensitive vulnerability reports.
