"""Tool result normalization models for SABER.

SandboxExecutionResult is the raw execution output from Sandbox. ToolResult is a
tool-agnostic normalized layer for parsers, agents, findings, and reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.core.sandbox import SandboxExecutionResult
from saber.models.session import MissionSession


class ToolResultStatus(StrEnum):
    """Normalized status for a tool execution result."""

    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolFinding:
    """Normalized finding produced from tool output."""

    title: str
    severity: str | None = None
    description: str | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate finding basics."""

        if not self.title.strip():
            raise ValueError("ToolFinding.title cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible finding data."""

        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ToolResult:
    """Normalized result for one tool action."""

    tool_name: str
    action: str
    status: ToolResultStatus
    session: MissionSession
    summary: str = ""
    findings: list[ToolFinding] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    return_code: int | None = None
    evidence_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate result basics."""

        if not self.tool_name.strip():
            raise ValueError("ToolResult.tool_name cannot be empty.")
        if not self.action.strip():
            raise ValueError("ToolResult.action cannot be empty.")

    @classmethod
    def from_sandbox_result(
        cls,
        tool_name: str,
        action: str,
        result: SandboxExecutionResult,
        findings: list[ToolFinding] | None = None,
        summary: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ToolResult:
        """Create ToolResult from SandboxExecutionResult."""

        status = ToolResultStatus.SUCCESS if result.allowed and result.return_code == 0 else ToolResultStatus.FAILED
        evidence_id = None

        if result.evidence is not None:
            evidence_id = getattr(result.evidence, "evidence_id", None) or getattr(result.evidence, "id", None)

        return cls(
            tool_name=tool_name,
            action=action,
            status=status,
            session=result.session,
            summary=summary if summary is not None else result.reason,
            findings=findings or [],
            raw_stdout=result.stdout,
            raw_stderr=result.stderr,
            return_code=result.return_code,
            evidence_id=evidence_id,
            metadata={
                **result.metadata,
                **(metadata or {}),
            },
        )

    def has_findings(self) -> bool:
        """Return whether normalized findings exist."""

        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible result data."""

        return {
            "tool_name": self.tool_name,
            "action": self.action,
            "status": self.status.value,
            "session_id": self.session.session_id,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_stdout": self.raw_stdout,
            "raw_stderr": self.raw_stderr,
            "return_code": self.return_code,
            "evidence_id": self.evidence_id,
            "metadata": self.metadata,
        }
