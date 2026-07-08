"""Sandbox inspection commands for SABER CLI."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.storage.evidence_index import EvidenceIndex


@dataclass(frozen=True)
class ToolAvailability:
    """Tool availability result."""

    tool: str
    available: bool
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible result."""

        return {
            "tool": self.tool,
            "available": self.available,
            "path": self.path,
        }


@dataclass(frozen=True)
class SandboxCheck:
    """Sandbox check result."""

    docker_available: bool
    docker_path: str | None
    tools: list[ToolAvailability] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible check."""

        return {
            "docker_available": self.docker_available,
            "docker_path": self.docker_path,
            "tools": [tool.to_dict() for tool in self.tools],
        }


class SandboxCommands:
    """Read-only sandbox/tool inspection helpers."""

    DEFAULT_TOOLS = (
        "nmap",
        "nuclei",
        "whatweb",
        "searchsploit",
        "subfinder",
        "amass",
        "dnsrecon",
        "nikto",
        "sqlmap",
    )

    def __init__(
        self,
        evidence_index: EvidenceIndex | None = None,
        tools: tuple[str, ...] | None = None,
    ) -> None:
        """Initialize sandbox commands."""

        self.evidence_index = evidence_index
        self.tools = tools if tools is not None else self.DEFAULT_TOOLS

    def check(self) -> SandboxCheck:
        """Check local sandbox/tool readiness."""

        docker_path = shutil.which("docker")
        tools = [
            ToolAvailability(
                tool=tool,
                available=shutil.which(tool) is not None,
                path=shutil.which(tool),
            )
            for tool in self.tools
        ]

        return SandboxCheck(
            docker_available=docker_path is not None,
            docker_path=docker_path,
            tools=tools,
        )

    def list_tools(self) -> list[ToolAvailability]:
        """List configured tool availability."""

        return self.check().tools

    def list_evidence(self, session_id: str) -> list[dict[str, Any]]:
        """List evidence for a session."""

        if self.evidence_index is None:
            raise RuntimeError("EvidenceIndex is required to list evidence.")
        return self.evidence_index.list_evidence(session_id)

    def evidence_paths(self, session_id: str) -> list[Path]:
        """Return evidence paths for a session."""

        return [Path(item["path"]) for item in self.list_evidence(session_id)]

    @staticmethod
    def format_check(check: SandboxCheck) -> str:
        """Format sandbox check for terminal output."""

        lines = ["SABER Sandbox Check", ""]

        docker_label = "OK" if check.docker_available else "WARN"
        lines.append(f"[{docker_label}] docker: {check.docker_path or 'not found'}")
        lines.append("")
        lines.append("Tools:")

        for tool in check.tools:
            label = "OK" if tool.available else "WARN"
            lines.append(f"[{label}] {tool.tool}: {tool.path or 'not found'}")

        return "\n".join(lines)
