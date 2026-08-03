"""Sandbox inspection commands for SABER CLI."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.core.docker_runner import DEFAULT_SHARED_IMAGE
from saber.storage.evidence_index import EvidenceIndex
from saber.tools.image_manifest import expected_executables, missing_in_image


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
    image: str = ""
    image_complete: bool | None = None
    missing_executables: list[str] = field(default_factory=list)
    image_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible check."""

        return {
            "docker_available": self.docker_available,
            "docker_path": self.docker_path,
            "tools": [tool.to_dict() for tool in self.tools],
            "image": self.image,
            "image_complete": self.image_complete,
            "missing_executables": list(self.missing_executables),
            "image_error": self.image_error,
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

    def check(self, image: str | None = None, inspect_image: bool = True) -> SandboxCheck:
        """Check sandbox readiness.

        The tool check asks the SANDBOX IMAGE, not the host. It used to call
        shutil.which() on the host, which is the wrong question entirely — agents
        never run on the host, every tool executes inside the container — so on a
        normal workstation it reported every tool "not found" and told the operator
        nothing. That blind spot is why a published image missing six contracted
        executables went unnoticed.
        """

        docker_path = shutil.which("docker")
        resolved_image = image or os.environ.get("SABER_SANDBOX_IMAGE", DEFAULT_SHARED_IMAGE)

        if not inspect_image or docker_path is None:
            return SandboxCheck(
                docker_available=docker_path is not None,
                docker_path=docker_path,
                tools=[],
                image=resolved_image,
                image_error=None if inspect_image else "image inspection skipped",
            )

        try:
            missing = missing_in_image(resolved_image)
        except RuntimeError as exc:
            return SandboxCheck(
                docker_available=True,
                docker_path=docker_path,
                tools=[],
                image=resolved_image,
                image_error=str(exc),
            )

        expected = expected_executables()
        missing_set = set(missing)
        tools = [
            ToolAvailability(tool=name, available=name not in missing_set)
            for name in expected
        ]

        return SandboxCheck(
            docker_available=True,
            docker_path=docker_path,
            tools=tools,
            image=resolved_image,
            image_complete=not missing,
            missing_executables=missing,
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

        docker_label = "OK" if check.docker_available else "FAIL"
        lines.append(f"[{docker_label}] docker: {check.docker_path or 'not found'}")
        lines.append(f"[  ] image: {check.image or 'unset'}")

        if check.image_error:
            lines.append(f"[FAIL] image not inspected: {check.image_error}")
            lines.append("")
            lines.append("Build it with: make sandbox-build")
            return "\n".join(lines)

        if check.image_complete:
            lines.append(
                f"[OK] every executable {len(check.tools)} tool contracts invoke is present"
            )
            return "\n".join(lines)

        if check.image_complete is False:
            lines.append(
                f"[FAIL] {len(check.missing_executables)} contracted executable(s) missing "
                "from the image"
            )
            lines.append("")
            for name in check.missing_executables:
                lines.append(f"  missing: {name}")
            lines.append("")
            lines.append(
                "Tools whose executable is missing fail at run time regardless of scope or "
                "autonomy. Rebuild with: make sandbox-build && make sandbox-verify"
            )

        return "\n".join(lines)
