"""Non-invasive MCP configuration discovery."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

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
    """Detect nonempty static credential clues; this cannot verify runtime auth."""
    env = server.get("env") or {}
    if not isinstance(env, dict):
        env = {}
    auth_keys = ("token", "api_key", "apikey", "auth", "secret", "password")

    def nonempty(value: Any) -> bool:
        return bool(value.strip()) if isinstance(value, str) else bool(value)

    for key, value in env.items():
        key_lower = str(key).lower()
        if any(fragment in key_lower for fragment in auth_keys) and nonempty(value):
            return True
    headers = server.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            key_lower = str(key).lower()
            if any(fragment in key_lower for fragment in auth_keys) and nonempty(value):
                return True
    return False


def _is_loopback_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _http_transport_risk(url: Any) -> str | None:
    """Return a risk hint only for classifiable, cleartext non-loopback HTTP."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urlsplit(url.strip())
        host = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme.lower() == "http" and host and not _is_loopback_host(host):
        return "non-loopback HTTP endpoint uses cleartext — review transport protection"
    return None


def _server_risk_notes(name: str, server: Dict[str, Any]) -> List[str]:
    notes: List[str] = []
    transport = _server_transport(server)
    if transport == "remote":
        transport_risk = _http_transport_risk(server.get("url"))
        if transport_risk:
            notes.append(transport_risk)
    joined = json.dumps(server).lower()
    for keyword in RISKY_TOOL_KEYWORDS:
        if keyword in joined or keyword in name.lower():
            notes.append(f"configuration mentions risky capability '{keyword}'")
            break
    return notes


def parse_mcp_configs(config_paths: List[Path] | None = None) -> Tuple[List[Dict[str, Any]], List[Path]]:
    paths = discover_mcp_config_paths() if config_paths is None else config_paths
    servers: List[Dict[str, Any]] = []
    for path in paths:
        if path.is_dir():
            metadata = path / "SERVER_METADATA.json"
            if metadata.exists():
                try:
                    payload = _load_json(metadata)
                    if not isinstance(payload, dict):
                        continue
                    servers.append(
                        {
                            "name": path.name,
                            "source": str(path),
                            "transport": "mcp_metadata",
                            "risk_notes": [],
                            "server_identifier": payload.get("serverIdentifier", path.name),
                        }
                    )
                except (OSError, ValueError):
                    continue
            continue
        try:
            payload = _load_json(path)
        except (OSError, ValueError):
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
