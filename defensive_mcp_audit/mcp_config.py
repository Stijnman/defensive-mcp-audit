"""Non-invasive MCP configuration discovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from defensive_mcp_audit.constants import MCP_CONFIG_CANDIDATES, RISKY_TOOL_KEYWORDS


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path)).resolve()


def discover_mcp_config_paths(extra_paths: List[Path] | None = None) -> List[Path]:
    paths: List[Path] = []
    seen = set()
    for candidate in MCP_CONFIG_CANDIDATES:
        path = _expand(candidate)
        if path.exists() and path not in seen:
            paths.append(path)
            seen.add(path)

    grok_root = _expand("~/.grok/projects")
    if grok_root.is_dir():
        for mcp_json in grok_root.glob("*/mcps/*/SERVER_METADATA.json"):
            parent = mcp_json.parent
            if parent not in seen:
                paths.append(parent)
                seen.add(parent)

    if extra_paths:
        for path in extra_paths:
            resolved = path.resolve()
            if resolved.exists() and resolved not in seen:
                paths.append(resolved)
                seen.add(resolved)
    return paths


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _extract_servers(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if "mcpServers" in payload and isinstance(payload["mcpServers"], dict):
        return payload["mcpServers"]
    if "servers" in payload and isinstance(payload["servers"], dict):
        return payload["servers"]
    return {}


def _server_transport(server: Dict[str, Any]) -> str:
    if "url" in server:
        return "remote"
    if "command" in server:
        return "stdio"
    return "unknown"


def _server_has_auth_hints(server: Dict[str, Any]) -> bool:
    env = server.get("env") or {}
    if not isinstance(env, dict):
        return False
    auth_keys = ("token", "api_key", "apikey", "auth", "secret", "password")
    for key, value in env.items():
        key_lower = str(key).lower()
        if any(fragment in key_lower for fragment in auth_keys) and value:
            return True
    headers = server.get("headers") or {}
    if isinstance(headers, dict):
        for key in headers:
            if "auth" in str(key).lower():
                return True
    return False


def _server_risk_notes(name: str, server: Dict[str, Any]) -> List[str]:
    notes: List[str] = []
    transport = _server_transport(server)
    if transport == "remote":
        notes.append("remote endpoint configured — verify TLS and auth")
    if not _server_has_auth_hints(server) and transport in {"remote", "stdio"}:
        notes.append("no obvious auth/env secret configured")
    joined = json.dumps(server).lower()
    for keyword in RISKY_TOOL_KEYWORDS:
        if keyword in joined or keyword in name.lower():
            notes.append(f"configuration mentions risky capability '{keyword}'")
            break
    return notes


def parse_mcp_configs(config_paths: List[Path] | None = None) -> Tuple[List[Dict[str, Any]], List[Path]]:
    paths = config_paths or discover_mcp_config_paths()
    servers: List[Dict[str, Any]] = []
    for path in paths:
        if path.is_dir():
            metadata = path / "SERVER_METADATA.json"
            if metadata.exists():
                try:
                    payload = _load_json(metadata)
                    servers.append(
                        {
                            "name": path.name,
                            "source": str(path),
                            "transport": "mcp_metadata",
                            "risk_notes": [],
                            "server_identifier": payload.get("serverIdentifier", path.name),
                        }
                    )
                except (OSError, json.JSONDecodeError):
                    continue
            continue
        try:
            payload = _load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        for name, server in _extract_servers(payload).items():
            if not isinstance(server, dict):
                continue
            servers.append(
                {
                    "name": name,
                    "source": str(path),
                    "transport": _server_transport(server),
                    "risk_notes": _server_risk_notes(name, server),
                    "has_auth_hints": _server_has_auth_hints(server),
                }
            )
    return servers, paths