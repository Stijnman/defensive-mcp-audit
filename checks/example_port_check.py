"""Example plugin: flag MCP-related listeners that are not localhost-bound."""

from __future__ import annotations

from typing import Any, Dict, List


def run_check(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    services = context.get("services", [])
    offenders = [
        service
        for service in services
        if service.get("classification") == "mcp_related"
        and not service.get("localhost_binding")
    ]
    if not offenders:
        return []
    return [
        {
            "id": "PLUGIN_MCP_NON_LOCALHOST",
            "category": "Plugins",
            "severity": "high",
            "title": "MCP-related service not bound to localhost",
            "value": [
                f"{item['address']}:{item['port']} ({item.get('process') or 'unknown'})"
                for item in offenders
            ],
            "note": "Example plugin check — bind MCP servers to 127.0.0.1 or ::1.",
        }
    ]