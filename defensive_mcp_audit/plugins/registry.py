"""Simple plugin registry for community defensive checks."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Callable, Dict, List

CheckFn = Callable[[Dict[str, Any]], List[Dict[str, Any]]]

_REGISTERED: List[CheckFn] = []


def register(check: CheckFn) -> CheckFn:
    _REGISTERED.append(check)
    return check


def discover_checks() -> None:
    """Import built-in and optional checks/ package modules."""
    _REGISTERED.clear()
    import checks as checks_pkg

    for module_info in pkgutil.iter_modules(checks_pkg.__path__, checks_pkg.__name__ + "."):
        if module_info.name.endswith(".example_port_check"):
            continue
        module = importlib.import_module(module_info.name)
        if hasattr(module, "run_check"):
            _REGISTERED.append(module.run_check)


def run_registered_checks(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for check in _REGISTERED:
        findings.extend(check(context))
    return findings