# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-06-23

### Added
- Docker runtime inspection (`docker ps` published port analysis)
- PyPI trusted publishing in `release.yml` + `pypi` GitHub environment
- `assets/social-preview.png` and `.github/social-preview.png`
- `docs/PYPI_SETUP.md` and `scripts/upload_social_preview.mjs`
- Docker unit tests

### Changed
- README PyPI badge and install instructions
- Roadmap: PyPI workflow and Docker inspection marked complete

## [0.3.1] - 2026-06-23

### Added
- Composite GitHub Action (`action/action.yml`) for one-click CI integration
- Issue and PR templates, `SECURITY.md`, `CODEOWNERS`, Dependabot config
- Release workflow attaching wheels/sdists to GitHub Releases
- Repository branding assets (`assets/logo.svg`, `assets/social-preview.svg`)
- Example consumer workflow and expanded README

### Changed
- README redesigned with badges, finding reference table, and sample output
- CONTRIBUTING.md updated for v0.3 plugin workflow

## [0.3.0] - 2026-06-23

### Added
- Proper Python package layout (`defensive_mcp_audit/`)
- Process-aware service classification (MCP-related / system / unknown)
- Weighted risk scoring to reduce false positives from OS services (Samba, etc.)
- Static MCP configuration discovery (Claude, Cursor, VS Code, Grok, `.mcp.json`)
- Plugin registry with example check in `checks/example_port_check.py`
- Unit test suite (`tests/`)
- Cross-platform listener fallback via `netstat` when `ss` is unavailable
- Self-contained HTML reports (embedded CSS, no Tailwind CDN)
- Expanded `SKILL.md` with triggers, commands, and finding reference

### Changed
- SARIF `informationUri` now points to the real GitHub repository
- Framework checks only report installed packages (less noise)
- Confused-deputy finding now requires actual MCP surface evidence
- CLI available via `python -m defensive_mcp_audit`
- Bumped risk thresholds for more realistic severity levels

### Fixed
- Placeholder author email in `pyproject.toml`
- Unused/broken README asset references removed
- Silent failures now log discovery errors to stderr
- `pip install` package entry point and module imports

## [0.2.0] - 2026-06-20

### Added
- Dynamic listening service discovery using `ss -tlnp`
- SARIF 2.1.0 emitter for GitHub Code Scanning integration
- HTML report generation
- Rich + Typer CLI with graceful fallback
- `pyproject.toml`, GitHub Actions workflow, `SKILL.md`

[0.3.2]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.3.2
[0.3.1]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.3.1
[0.3.0]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.3.0
[0.2.0]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.2.0