"""Shared constants for defensive-mcp-audit."""

from __future__ import annotations

import re

VERSION = "0.3.1"
REPO_URL = "https://github.com/Stijnman/defensive-mcp-audit"

MCP_COMMON_PORTS = frozenset({3000, 5000, 5173, 6274, 6277, 8000, 8080, 8765, 9000, 11434})

MCP_PROCESS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"mcp",
        r"ollama",
        r"uvicorn",
        r"gunicorn",
        r"langchain",
        r"crewai",
        r"autogen",
        r"hermes",
        r"fastapi",
        r"streamlit",
        r"computer-use",
        r"codex",
        r"node",
        r"npx",
        r"gradio",
        r"vllm",
        r"lmstudio",
    )
]

SYSTEM_PROCESS_ALLOWLIST = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"smbd",
        r"nmbd",
        r"systemd-resolve",
        r"docker",
        r"containerd",
        r"sshd",
        r"cupsd",
        r"avahi",
        r"dnsmasq",
        r"libvirtd",
        r"qemu",
        r"rpc\.",
        r"winbind",
        r"systemd",
    )
]

RISKY_TOOL_KEYWORDS = (
    "shell",
    "exec",
    "write",
    "delete",
    "bash",
    "sudo",
    "run_command",
    "terminal",
    "filesystem",
)

FRAMEWORK_PACKAGES = (
    "autogen",
    "crewai",
    "langchain",
    "semantic-kernel",
    "openai",
    "mcp",
)

MCP_CONFIG_CANDIDATES = (
    "~/.config/Claude/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.config/Code/User/mcp.json",
    "~/.config/Grok/mcp.json",
    ".mcp.json",
)