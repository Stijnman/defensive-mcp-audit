"""Plugin registry for custom defensive checks."""

from defensive_mcp_audit.plugins.registry import discover_checks, run_registered_checks

__all__ = ["discover_checks", "run_registered_checks"]