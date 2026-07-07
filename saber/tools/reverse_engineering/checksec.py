"""Checksec wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class ChecksecWrapper(BaseToolWrapper):
    """Wrapper for checksec binary hardening analysis."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize checksec wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="checksec",
                image="saber/checksec:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="ChecksecWrapper",
                default_timeout_seconds=300,
                default_metadata={"tool_family": "reverse_engineering", "tool": "checksec"},
            ),
        )

    def binary(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        output_format: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run checksec against one binary."""

        return self.run(
            target=target,
            session=session,
            action="binary",
            binary_path=binary_path,
            output_format=output_format,
            metadata=metadata,
        )

    def directory(
        self,
        target: Target,
        session: MissionSession,
        directory_path: str,
        output_format: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run checksec against binaries in a directory."""

        return self.run(
            target=target,
            session=session,
            action="directory",
            directory_path=directory_path,
            output_format=output_format,
            metadata=metadata,
        )

    def kernel(
        self,
        target: Target,
        session: MissionSession,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run checksec kernel checks."""

        return self.run(
            target=target,
            session=session,
            action="kernel",
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a checksec ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            **(kwargs.get("metadata") or {}),
        }

        if action == "binary":
            binary_path = self._required_string(kwargs, "binary_path")
            command = ["checksec", "--file", binary_path]
            output_format = kwargs.get("output_format")
            if output_format:
                output_format = self._validate_output_format(output_format)
                command.append(f"--output={output_format}")

            return ToolCommand(
                command=command,
                action="binary",
                evidence_title=f"checksec binary: {binary_path}",
                evidence_relative_dir="reverse_engineering/checksec/binary",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "binary_path": binary_path, "output_format": output_format},
            )

        if action == "directory":
            directory_path = self._required_string(kwargs, "directory_path")
            command = ["checksec", "--dir", directory_path]
            output_format = kwargs.get("output_format")
            if output_format:
                output_format = self._validate_output_format(output_format)
                command.append(f"--output={output_format}")

            return ToolCommand(
                command=command,
                action="directory",
                evidence_title=f"checksec directory: {directory_path}",
                evidence_relative_dir="reverse_engineering/checksec/directory",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "directory_path": directory_path, "output_format": output_format},
            )

        if action == "kernel":
            return ToolCommand(
                command=["checksec", "--kernel"],
                action="kernel",
                evidence_title="checksec kernel",
                evidence_relative_dir="reverse_engineering/checksec/kernel",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata=metadata,
            )

        raise ValueError(f"Unsupported checksec action: {action}")

    @staticmethod
    def _validate_output_format(value: Any) -> str:
        """Validate checksec output format."""

        output_format = str(value).strip().lower()
        if output_format not in {"cli", "csv", "json", "xml"}:
            raise ValueError("output_format must be one of: cli, csv, json, xml")
        return output_format

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
