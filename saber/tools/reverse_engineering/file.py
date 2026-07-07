"""file command wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class FileWrapper(BaseToolWrapper):
    """Wrapper for Unix file type identification."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize file wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="file",
                image="saber/file:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="FileWrapper",
                default_timeout_seconds=120,
                default_metadata={"tool_family": "reverse_engineering", "tool": "file"},
            ),
        )

    def identify(
        self,
        target: Target,
        session: MissionSession,
        file_path: str,
        brief: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Identify one file."""

        return self.run(
            target=target,
            session=session,
            action="identify",
            file_path=file_path,
            brief=brief,
            metadata=metadata,
        )

    def mime(
        self,
        target: Target,
        session: MissionSession,
        file_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Identify MIME type for one file."""

        return self.run(
            target=target,
            session=session,
            action="mime",
            file_path=file_path,
            metadata=metadata,
        )

    def directory(
        self,
        target: Target,
        session: MissionSession,
        directory_path: str,
        recursive: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Identify files in a directory."""

        return self.run(
            target=target,
            session=session,
            action="directory",
            directory_path=directory_path,
            recursive=recursive,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a file ToolCommand."""

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

        if action == "identify":
            file_path = self._required_string(kwargs, "file_path")
            command = ["file"]
            if bool(kwargs.get("brief", False)):
                command.append("-b")
            command.append(file_path)

            return ToolCommand(
                command=command,
                action="identify",
                evidence_title=f"file identify: {file_path}",
                evidence_relative_dir="reverse_engineering/file/identify",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "file_path": file_path, "brief": bool(kwargs.get("brief", False))},
            )

        if action == "mime":
            file_path = self._required_string(kwargs, "file_path")
            return ToolCommand(
                command=["file", "--mime", file_path],
                action="mime",
                evidence_title=f"file MIME: {file_path}",
                evidence_relative_dir="reverse_engineering/file/mime",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "file_path": file_path},
            )

        if action == "directory":
            directory_path = self._required_string(kwargs, "directory_path")
            command = ["find", directory_path, "-type", "f", "-maxdepth", "1", "-exec", "file", "{}", ";"]
            recursive = bool(kwargs.get("recursive", False))
            if recursive:
                command = ["find", directory_path, "-type", "f", "-exec", "file", "{}", ";"]

            return ToolCommand(
                command=command,
                action="directory",
                evidence_title=f"file directory: {directory_path}",
                evidence_relative_dir="reverse_engineering/file/directory",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "directory_path": directory_path, "recursive": recursive},
            )

        raise ValueError(f"Unsupported file action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
