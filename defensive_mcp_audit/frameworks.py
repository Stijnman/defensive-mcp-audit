"""Installed AI framework version discovery."""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Dict, List

from defensive_mcp_audit.constants import FRAMEWORK_PACKAGES


def check_package_version(package_name: str) -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package_name],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "not installed"


def framework_findings() -> List[Dict[str, Any]]:
    installed = []
    for package in FRAMEWORK_PACKAGES:
        version = check_package_version(package)
        if version != "not installed":
            installed.append({"package": package, "version": version})
    if not installed:
        return []
    return [
        {
            "id": "FRAMEWORK_INVENTORY",
            "category": "Dependencies",
            "severity": "info",
            "title": f"Detected {len(installed)} AI/MCP-related Python packages",
            "value": installed,
            "note": "Review installed versions against vendor security advisories.",
        }
    ]