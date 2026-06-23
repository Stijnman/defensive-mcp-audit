"""Core audit orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from defensive_mcp_audit.constants import VERSION
from defensive_mcp_audit.docker_runtime import docker_findings
from defensive_mcp_audit.frameworks import framework_findings
from defensive_mcp_audit.mcp_config import parse_mcp_configs
from defensive_mcp_audit.network import discover_listening_services, enrich_services
from defensive_mcp_audit.plugins.registry import discover_checks, run_registered_checks
from defensive_mcp_audit.scoring import (
    compute_risk_level,
    dedupe_recommendations,
    mcp_related_services,
    risky_mcp_exposure,
)


def get_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_mcp_environment(
    *,
    ss_output: Optional[str] = None,
    enable_plugins: bool = True,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "timestamp": get_timestamp(),
        "audit_type": "defensive_mcp_agent_audit",
        "version": VERSION,
        "findings": [],
        "risk_score": 0,
        "risk_level": "low",
        "recommendations": [],
        "services_discovered": [],
        "mcp_servers_configured": [],
        "mcp_config_paths": [],
    }

    services = enrich_services(discover_listening_services(ss_output=ss_output))
    report["services_discovered"] = services

    mcp_servers, config_paths = parse_mcp_configs()
    report["mcp_servers_configured"] = mcp_servers
    report["mcp_config_paths"] = [str(path) for path in config_paths]

    recommendations: List[str] = []
    findings: List[Dict[str, Any]] = []
    risk_score = 0

    risky_mcp = risky_mcp_exposure(services)
    risky_unknown = [
        service
        for service in services
        if service.get("classification") == "unknown" and service.get("risky_binding")
    ]
    risky_system = [
        service
        for service in services
        if service.get("classification") == "system" and service.get("risky_binding")
    ]

    if risky_mcp:
        risk_score += sum(int(service.get("risk_weight", 0)) for service in risky_mcp)
        findings.append(
            {
                "id": "MCP_EXPOSED_NON_LOCALHOST",
                "category": "Network Exposure",
                "severity": "high",
                "title": "MCP-related services listening on non-localhost interfaces",
                "value": [
                    f"{item['address']}:{item['port']} ({item.get('process') or 'unknown'})"
                    for item in risky_mcp
                ],
                "note": "Bind MCP and agent servers to 127.0.0.1 or ::1 to reduce DNS rebinding and LAN exposure risk.",
            }
        )
        recommendations.extend(
            [
                "Bind MCP and agent HTTP/WebSocket servers to 127.0.0.1 only",
                "Require authentication tokens on every MCP endpoint",
            ]
        )

    if risky_unknown:
        risk_score += sum(int(service.get("risk_weight", 0)) for service in risky_unknown)
        findings.append(
            {
                "id": "UNKNOWN_EXPOSED_LISTENER",
                "category": "Network Exposure",
                "severity": "medium",
                "title": "Unclassified services listening on all interfaces",
                "value": [
                    f"{item['address']}:{item['port']} ({item.get('process') or 'unknown'})"
                    for item in risky_unknown
                ],
                "note": "Review whether these listeners are required. Unknown 0.0.0.0 bindings increase attack surface.",
            }
        )

    if risky_system:
        findings.append(
            {
                "id": "SYSTEM_EXPOSED_LISTENER",
                "category": "Network Exposure",
                "severity": "info",
                "title": "Known system services listening on all interfaces",
                "value": [
                    f"{item['address']}:{item['port']} ({item.get('process') or 'unknown'})"
                    for item in risky_system
                ],
                "note": "These look like standard OS services (e.g. Samba). They are noted for completeness but do not heavily affect MCP risk scoring.",
            }
        )

    mcp_local = [
        service
        for service in mcp_related_services(services)
        if service.get("localhost_binding")
    ]
    if mcp_local:
        findings.append(
            {
                "id": "MCP_LOCALHOST_OK",
                "category": "Network Exposure",
                "severity": "info",
                "title": f"{len(mcp_local)} MCP-related service(s) bound to localhost",
                "value": [f"{item['address']}:{item['port']}" for item in mcp_local[:10]],
                "note": "Localhost binding is the recommended default for MCP servers on developer machines.",
            }
        )

    if services:
        findings.append(
            {
                "id": "LISTENING_SERVICES",
                "category": "Network Exposure",
                "severity": "info",
                "title": f"Discovered {len(services)} listening TCP services",
                "value": [
                    f"{item['address']}:{item['port']} [{item.get('classification', 'unknown')}]"
                    for item in services[:15]
                ],
                "note": "Full inventory for review. MCP-related entries are weighted more heavily in risk scoring.",
            }
        )

    findings.extend(framework_findings())

    docker_items = docker_findings()
    if docker_items:
        for finding in docker_items:
            if finding.get("id") == "DOCKER_RISKY_PUBLISH":
                risk_score += 10
        findings.extend(docker_items)
        recommendations.append(
            "Bind Docker-published MCP ports to 127.0.0.1 (e.g. -p 127.0.0.1:8080:8080)"
        )

    if mcp_servers:
        risky_configs = [server for server in mcp_servers if server.get("risk_notes")]
        findings.append(
            {
                "id": "MCP_CONFIG_DISCOVERED",
                "category": "MCP Configuration",
                "severity": "info",
                "title": f"Found {len(mcp_servers)} configured MCP server(s)",
                "value": [
                    {
                        "name": server["name"],
                        "source": server["source"],
                        "transport": server.get("transport"),
                        "risk_notes": server.get("risk_notes", []),
                    }
                    for server in mcp_servers
                ],
                "note": "Static, read-only inspection of common MCP client configuration files.",
            }
        )
        if risky_configs:
            risk_score += min(20, 5 * len(risky_configs))
            findings.append(
                {
                    "id": "MCP_CONFIG_RISK",
                    "category": "MCP Configuration",
                    "severity": "medium",
                    "title": "Potentially risky MCP server configuration patterns detected",
                    "value": [
                        {"name": server["name"], "notes": server.get("risk_notes", [])}
                        for server in risky_configs
                    ],
                    "note": "Review remote endpoints, missing auth hints, and high-privilege tool exposure.",
                }
            )
            recommendations.append(
                "Audit configured MCP servers for least-privilege tools and explicit authentication"
            )

    has_mcp_surface = bool(mcp_related_services(services) or mcp_servers)
    if has_mcp_surface and (risky_mcp or mcp_local):
        confused_severity = "high" if risky_mcp else "medium"
        if risky_mcp:
            risk_score += 15
        elif mcp_local:
            risk_score += 5
        findings.append(
            {
                "id": "CONFUSED_DEPUTY_RISK",
                "category": "MCP / Agent Trust Boundary",
                "severity": confused_severity,
                "title": "Potential confused-deputy / localhost trust-boundary risk",
                "value": {
                    "mcp_services": len(mcp_related_services(services)),
                    "risky_mcp_bindings": len(risky_mcp),
                    "configured_mcp_servers": len(mcp_servers),
                },
                "note": "Web-enabled agents or malicious pages (DNS rebinding) may reach local MCP endpoints. Enforce auth, input validation, and localhost-only bindings.",
            }
        )
        recommendations.extend(
            [
                "Require authentication tokens on all MCP/WebSocket/HTTP endpoints",
                "Sandbox web-facing agent tools and validate untrusted input",
            ]
        )

    if enable_plugins:
        discover_checks()
        plugin_findings = run_registered_checks({"services": services, "mcp_servers": mcp_servers})
        for finding in plugin_findings:
            if finding.get("severity") in {"high", "critical"}:
                risk_score += 10
            elif finding.get("severity") == "medium":
                risk_score += 5
        findings.extend(plugin_findings)

    recommendations.extend(
        [
            "Keep AI agent frameworks and MCP servers up to date",
            "Run high-privilege MCP tools inside containers or VMs when possible",
            "Disable unnecessary MCP tools when not actively needed",
            "Apply least-privilege: expose only the tools an agent requires",
        ]
    )

    report["findings"] = findings
    report["recommendations"] = dedupe_recommendations(recommendations)
    report["risk_score"] = risk_score
    report["risk_level"] = compute_risk_level(report["risk_score"])
    return report