"""Risk scoring helpers."""

from __future__ import annotations

from typing import Any, Dict, List


def compute_risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "low"


def score_services(services: List[Dict[str, Any]]) -> int:
    return sum(int(service.get("risk_weight", 0)) for service in services)


def mcp_related_services(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [service for service in services if service.get("classification") == "mcp_related"]


def risky_mcp_exposure(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        service
        for service in services
        if service.get("classification") == "mcp_related" and service.get("risky_binding")
    ]


def dedupe_recommendations(recommendations: List[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for item in recommendations:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered