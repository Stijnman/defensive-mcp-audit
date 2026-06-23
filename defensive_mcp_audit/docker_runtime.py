"""Read-only Docker runtime inspection for exposed MCP-related ports."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List

from defensive_mcp_audit.constants import MCP_COMMON_PORTS


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def inspect_docker_publishers() -> List[Dict[str, Any]]:
    if not _docker_available():
        return []
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{json .}}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return []
    except (OSError, subprocess.TimeoutExpired):
        return []

    containers: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        ports_field = payload.get("Ports") or ""
        published = []
        for segment in ports_field.split(","):
            segment = segment.strip()
            if "->" not in segment:
                continue
            host_part, container_part = segment.split("->", 1)
            host_part = host_part.strip()
            container_port = container_part.split("/", 1)[0]
            host_binding = host_part.rsplit(":", 1)[0] if ":" in host_part else host_part
            try:
                host_port = int(host_part.rsplit(":", 1)[-1])
            except ValueError:
                host_port = None
            risky_binding = host_binding in ("0.0.0.0", "::", "*", "")
            mcp_port = host_port in MCP_COMMON_PORTS if host_port else False
            published.append(
                {
                    "mapping": segment,
                    "host_binding": host_binding or "0.0.0.0",
                    "host_port": host_port,
                    "container_port": container_port,
                    "risky_binding": risky_binding,
                    "mcp_port": mcp_port,
                }
            )
        if published:
            containers.append(
                {
                    "name": payload.get("Names"),
                    "image": payload.get("Image"),
                    "published_ports": published,
                }
            )
    return containers


def docker_findings() -> List[Dict[str, Any]]:
    containers = inspect_docker_publishers()
    if not containers:
        return []

    risky = []
    for container in containers:
        for port in container["published_ports"]:
            if port.get("risky_binding") or port.get("mcp_port"):
                risky.append(
                    {
                        "container": container["name"],
                        "image": container["image"],
                        **port,
                    }
                )

    findings: List[Dict[str, Any]] = [
        {
            "id": "DOCKER_PUBLISHED_PORTS",
            "category": "Container Runtime",
            "severity": "info",
            "title": f"Detected {len(containers)} running container(s) with published ports",
            "value": containers,
            "note": "Read-only docker ps inspection. Review published port bindings for MCP-related exposure.",
        }
    ]
    if risky:
        findings.append(
            {
                "id": "DOCKER_RISKY_PUBLISH",
                "category": "Container Runtime",
                "severity": "medium",
                "title": "Containers publishing ports on all interfaces or common MCP ports",
                "value": risky,
                "note": "Prefer 127.0.0.1 port bindings (-p 127.0.0.1:PORT:PORT) for MCP/agent containers.",
            }
        )
    return findings