"""Network discovery and service classification."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from defensive_mcp_audit.constants import (
    MCP_COMMON_PORTS,
    MCP_PROCESS_PATTERNS,
    SYSTEM_PROCESS_ALLOWLIST,
)


def is_risky_binding(address: str) -> bool:
    normalized = address.strip("[]%lo").split("%", 1)[0]
    if normalized in ("0.0.0.0", "::", "*", "0:0:0:0:0:0:0:0"):
        return True
    if normalized.startswith("::ffff:"):
        return True
    return False


def is_localhost_binding(address: str) -> bool:
    normalized = address.strip("[]").split("%", 1)[0]
    if normalized in ("127.0.0.1", "::1", "localhost"):
        return True
    if normalized.startswith("127."):
        return True
    return False


def classify_service(process: str, port: int) -> str:
    process_lower = (process or "").lower()
    for pattern in MCP_PROCESS_PATTERNS:
        if pattern.search(process_lower):
            return "mcp_related"
    if port in MCP_COMMON_PORTS:
        return "mcp_related"
    for pattern in SYSTEM_PROCESS_ALLOWLIST:
        if pattern.search(process_lower):
            return "system"
    return "unknown"


def _parse_ss_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.split()
    if len(parts) < 5:
        return None
    local_addr = parts[3]
    process_info = parts[5] if len(parts) > 5 else ""
    if ":" not in local_addr:
        return None
    if local_addr.startswith("["):
        address, port_part = local_addr.rsplit(":", 1)
    else:
        address, port_part = local_addr.rsplit(":", 1)
    try:
        port = int(port_part)
    except ValueError:
        return None

    process = ""
    pid = ""
    if "pid=" in process_info:
        try:
            pid = process_info.split("pid=")[1].split(",")[0]
            if '"' in process_info:
                process = process_info.split('"')[1]
        except (IndexError, ValueError):
            pass

    classification = classify_service(process, port)
    return {
        "port": port,
        "address": address,
        "process": process,
        "pid": pid,
        "classification": classification,
        "risky_binding": is_risky_binding(address),
        "localhost_binding": is_localhost_binding(address),
        "raw": line.strip(),
    }


def _parse_netstat_line(line: str) -> Optional[Dict[str, Any]]:
    if "LISTEN" not in line:
        return None
    parts = line.split()
    if len(parts) < 4:
        return None
    local_addr = parts[3] if platform.system() == "Darwin" else parts[1]
    if ":" not in local_addr:
        return None
    if local_addr.startswith("["):
        address, port_part = local_addr.rsplit(":", 1)
        address = address.strip("[]")
    else:
        address, port_part = local_addr.rsplit(":", 1)
    try:
        port = int(port_part)
    except ValueError:
        return None
    classification = classify_service("", port)
    return {
        "port": port,
        "address": address,
        "process": "",
        "pid": "",
        "classification": classification,
        "risky_binding": is_risky_binding(address),
        "localhost_binding": is_localhost_binding(address),
        "raw": line.strip(),
    }


def discover_listening_services(ss_output: Optional[str] = None) -> List[Dict[str, Any]]:
    """Discover listening TCP services using the best available platform tool."""
    services: List[Dict[str, Any]] = []
    errors: List[str] = []

    if ss_output is not None:
        for line in ss_output.splitlines()[1:]:
            parsed = _parse_ss_line(line)
            if parsed:
                services.append(parsed)
        return services

    if shutil.which("ss"):
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[1:]:
                    parsed = _parse_ss_line(line)
                    if parsed:
                        services.append(parsed)
                return services
            errors.append(f"ss exited with code {result.returncode}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"ss failed: {exc}")

    netstat_cmd = ["netstat", "-an"]
    if platform.system() in ("Linux", "Darwin"):
        netstat_cmd = ["netstat", "-tln"]
    if shutil.which("netstat"):
        try:
            result = subprocess.run(
                netstat_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parsed = _parse_netstat_line(line)
                    if parsed:
                        services.append(parsed)
                if services:
                    return services
            errors.append("netstat returned no parseable listeners")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"netstat failed: {exc}")

    if errors and not services:
        sys.stderr.write(
            "defensive-mcp-audit: could not discover listeners: "
            + "; ".join(errors)
            + "\n"
        )
    return services


def enrich_services(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach scoring hints used by the audit engine."""
    enriched = []
    for service in services:
        item = dict(service)
        classification = item.get("classification", "unknown")
        risky = item.get("risky_binding", False)
        if classification == "mcp_related" and risky:
            item["risk_weight"] = 40
            item["risk_tier"] = "high"
        elif classification == "unknown" and risky:
            item["risk_weight"] = 12
            item["risk_tier"] = "medium"
        elif classification == "system" and risky:
            item["risk_weight"] = 2
            item["risk_tier"] = "info"
        else:
            item["risk_weight"] = 0
            item["risk_tier"] = "none"
        enriched.append(item)
    return enriched