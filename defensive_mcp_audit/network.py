"""Network discovery and service classification."""
from __future__ import annotations

import ipaddress
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


def _unbracket_address(address: str) -> str:
    """Remove only a matching IPv6 bracket pair, not arbitrary characters."""
    address = address.strip()
    if address.startswith("[") and address.endswith("]"):
        return address[1:-1]
    return address


def _ip_address(address: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse an IP literal, ignoring a valid IPv6 zone identifier for classification."""
    normalized = _unbracket_address(address)
    # Ignore an optional interface zone for classification. Some tools append
    # one even to IPv4 loopback output, and existing callers rely on that form.
    host = normalized.split("%", 1)[0]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_risky_binding(address: str) -> bool:
    """Return whether a listener binds beyond loopback, including explicit IPs."""
    normalized = _unbracket_address(address)
    if normalized == "*":
        return True
    parsed = _ip_address(normalized)
    if parsed is None:
        return False
    # A mapped IPv6 socket address has the effective binding semantics of its
    # embedded IPv4 address; in particular ::ffff:127.0.0.1 is loopback.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return not parsed.is_loopback


def is_localhost_binding(address: str) -> bool:
    normalized = _unbracket_address(address)
    if normalized.lower() == "localhost":
        return True
    parsed = _ip_address(normalized)
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.is_loopback


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


def _parse_endpoint(endpoint: str) -> Optional[tuple[str, int]]:
    """Parse ss/netstat endpoint forms, including macOS host.port notation."""
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        if closing < 0 or closing + 1 >= len(endpoint) or endpoint[closing + 1] != ":":
            return None
        address = endpoint[1:closing]
        port_text = endpoint[closing + 2 :]
    elif ":" in endpoint and endpoint.rsplit(":", 1)[1].isdigit():
        address, port_text = endpoint.rsplit(":", 1)
    elif "." in endpoint and endpoint.rsplit(".", 1)[1].isdigit():
        # Darwin netstat uses host.port; splitting at the final dot handles
        # IPv4 and scoped or unscoped IPv6 host strings without ambiguity.
        address, port_text = endpoint.rsplit(".", 1)
    else:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 0 <= port <= 65535:
        return None
    return address, port


def _parse_ss_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.split()
    if len(parts) < 5:
        return None
    # ss normally starts with State. Some versions include a Netid column.
    state_index = 0 if parts[0].upper() == "LISTEN" else 1
    if len(parts) <= state_index or parts[state_index].upper() != "LISTEN":
        return None
    local_index = 3 if state_index == 0 else 4
    if len(parts) <= local_index + 1:
        return None
    endpoint = _parse_endpoint(parts[local_index])
    if endpoint is None:
        return None
    address, port = endpoint
    process_info = " ".join(parts[local_index + 2 :])

    process = ""
    pid = ""
    pid_match = re.search(r"\bpid=(\d+)\b", process_info)
    if pid_match:
        pid = pid_match.group(1)
        process_match = re.search(r'\("([^"]+)"', process_info)
        if process_match:
            process = process_match.group(1)

    return {
        "port": port,
        "address": address,
        "process": process,
        "pid": pid,
        "classification": classify_service(process, port),
        "risky_binding": is_risky_binding(address),
        "localhost_binding": is_localhost_binding(address),
        "raw": line.strip(),
    }


def _parse_netstat_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.split()
    if len(parts) < 4:
        return None
    states = {part.upper() for part in parts}
    if not states.intersection({"LISTEN", "LISTENING"}):
        return None

    system = platform.system()
    # Windows netstat columns: Proto, Local Address, Foreign Address, State, PID.
    # Linux and Darwin netstat put local address in column four (index 3).
    local_index = 1 if system == "Windows" or "LISTENING" in states else 3
    if len(parts) <= local_index:
        return None
    endpoint = _parse_endpoint(parts[local_index])
    if endpoint is None:
        return None
    address, port = endpoint
    return {
        "port": port,
        "address": address,
        "process": "",
        "pid": "",
        "classification": classify_service("", port),
        "risky_binding": is_risky_binding(address),
        "localhost_binding": is_localhost_binding(address),
        "raw": line.strip(),
    }


def discover_listening_services(ss_output: Optional[str] = None) -> List[Dict[str, Any]]:
    """Discover listening TCP services using the best available platform tool."""
    services: List[Dict[str, Any]] = []
    errors: List[str] = []

    if ss_output is not None:
        for line in ss_output.splitlines():
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
                for line in result.stdout.splitlines():
                    parsed = _parse_ss_line(line)
                    if parsed:
                        services.append(parsed)
                return services
            errors.append(f"ss exited with code {result.returncode}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"ss failed: {exc}")

    system = platform.system()
    if system == "Darwin":
        netstat_cmd = ["netstat", "-an", "-p", "tcp"]
    elif system == "Windows":
        netstat_cmd = ["netstat", "-ano"]
    else:
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
