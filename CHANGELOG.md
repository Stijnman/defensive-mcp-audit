# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-20

### Added
- Dynamic listening service discovery using `ss -tlnp` (replaces hardcoded ports)
- Automatic detection of risky non-localhost bindings (`0.0.0.0`, `::`, etc.)
- SARIF 2.1.0 emitter for GitHub Code Scanning integration
- Self-contained HTML report generation (Tailwind CDN, beautiful out-of-the-box)
- Rich + Typer CLI with graceful fallback when dependencies are missing
- Timezone-aware timestamps (fixed `datetime.utcnow()` deprecation)
- Multi-format output support (`text`, `json`, `sarif`, `html`)
- `pyproject.toml` for modern Python packaging and `pip install` support
- CLI entry point (`defensive-mcp-audit` command after installation)
- `SKILL.md` for easy integration into local AI agent skill ecosystems
- Professional open-source files: `README.md`, `LICENSE`, `CONTRIBUTING.md`, `.gitignore`
- GitHub Actions workflow with SARIF upload and HTML report artifact
- Initial issues for v0.3.0 roadmap (plugin architecture + MCP manifest discovery)

### Changed
- Risk scoring and severity categorization improved
- Findings now include structured `id`, `category`, `severity`, `title`, `value`, and `note`
- Recommendations are more targeted and actionable
- Overall code quality and maintainability significantly improved

### Security
- Strictly defensive scope maintained (read-only inspection only)
- Clear warnings about localhost exposure and confused-deputy risks in MCP environments

## [0.1.0] - 2026-06-20 (Initial prototype)

- Basic hardcoded port checking
- Simple version detection for AutoGen
- Static recommendations
- JSON report output

[0.2.0]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.2.0
[0.1.0]: https://github.com/Stijnman/defensive-mcp-audit/releases/tag/v0.1.0