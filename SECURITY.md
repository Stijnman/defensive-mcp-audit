# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting a vulnerability

If you find a security issue **in this tool** (not in your local MCP setup), please report it responsibly:

1. **Preferred:** Open a [GitHub Security Advisory](https://github.com/Stijnman/defensive-mcp-audit/security/advisories/new) (private).
2. **Alternative:** Open an issue with the `security` label and avoid posting exploit details publicly.

We aim to acknowledge reports within **72 hours**.

## Scope

This project is **defensive only**. We will not accept contributions that:

- Add exploitation, payload generation, or active attack capabilities
- Probe remote systems without explicit user intent
- Bypass authentication on third-party services

Reports about **risks discovered by the audit on your machine** (exposed MCP servers, weak bindings, etc.) are expected audit output — fix your local configuration using the tool's recommendations.

## Safe harbor

Good-faith security research on the tool itself is welcome. Please keep testing local to your own environment.