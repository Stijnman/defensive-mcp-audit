"""SARIF output generation."""

from __future__ import annotations

from typing import Any, Dict

from defensive_mcp_audit.constants import REPO_URL, VERSION

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "defensive-mcp-audit",
                        "version": report.get("version", VERSION),
                        "informationUri": REPO_URL,
                    }
                },
                "results": [],
            }
        ],
    }
    for finding in report.get("findings", []):
        if finding.get("severity") == "info":
            continue
        result = {
            "ruleId": finding.get("id", "UNKNOWN"),
            "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "info"), "note"),
            "message": {
                "text": f"{finding.get('title', '')}: {finding.get('note', '')}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "local-environment"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        sarif["runs"][0]["results"].append(result)
    return sarif