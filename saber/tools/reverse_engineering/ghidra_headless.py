"""Ghidra headless analyzer wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class GhidraHeadlessWrapper(BaseToolWrapper):
    """Wrapper for Ghidra analyzeHeadless workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Ghidra headless wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="ghidra_headless",
                image="saber/ghidra-headless:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="GhidraHeadlessWrapper",
                default_timeout_seconds=3600,
                default_metadata={"tool_family": "reverse_engineering", "tool": "ghidra_headless"},
            ),
        )

    def analyze_binary(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        project_dir: str,
        project_name: str,
        script_path: str | None = None,
        script_args: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Import and analyze a binary in Ghidra headless."""

        return self.run(
            target=target,
            session=session,
            action="analyze_binary",
            binary_path=binary_path,
            project_dir=project_dir,
            project_name=project_name,
            script_path=script_path,
            script_args=script_args or [],
            metadata=metadata,
        )

    def run_script(
        self,
        target: Target,
        session: MissionSession,
        project_dir: str,
        project_name: str,
        script_path: str,
        script_args: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Ghidra script against an existing project."""

        return self.run(
            target=target,
            session=session,
            action="run_script",
            project_dir=project_dir,
            project_name=project_name,
            script_path=script_path,
            script_args=script_args or [],
            metadata=metadata,
        )

    def export_analysis(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        project_dir: str,
        project_name: str,
        export_script: str,
        output_file: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Analyze a binary and export analysis with a script."""

        return self.run(
            target=target,
            session=session,
            action="export_analysis",
            binary_path=binary_path,
            project_dir=project_dir,
            project_name=project_name,
            export_script=export_script,
            output_file=output_file,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Ghidra headless ToolCommand."""

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

        if action == "analyze_binary":
            binary_path = self._required_string(kwargs, "binary_path")
            project_dir = self._required_string(kwargs, "project_dir")
            project_name = self._required_string(kwargs, "project_name")
            command = [
                "analyzeHeadless",
                project_dir,
                project_name,
                "-import",
                binary_path,
                "-overwrite",
                "-analysisTimeoutPerFile",
                str(self._positive_int(kwargs.get("analysis_timeout_seconds", 1800), "analysis_timeout_seconds")),
            ]

            script_path = kwargs.get("script_path")
            script_args = self._string_list(kwargs.get("script_args") or [])
            if script_path:
                command.extend(["-postScript", str(script_path), *script_args])

            return ToolCommand(
                command=command,
                action="analyze_binary",
                evidence_title=f"Ghidra analyze binary: {binary_path}",
                evidence_relative_dir="reverse_engineering/ghidra_headless/analyze_binary",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "binary_path": binary_path,
                    "project_dir": project_dir,
                    "project_name": project_name,
                    "script_path": script_path,
                    "script_args": script_args,
                },
            )

        if action == "run_script":
            project_dir = self._required_string(kwargs, "project_dir")
            project_name = self._required_string(kwargs, "project_name")
            script_path = self._required_string(kwargs, "script_path")
            script_args = self._string_list(kwargs.get("script_args") or [])

            return ToolCommand(
                command=["analyzeHeadless", project_dir, project_name, "-process", "-postScript", script_path, *script_args],
                action="run_script",
                evidence_title=f"Ghidra run script: {script_path}",
                evidence_relative_dir="reverse_engineering/ghidra_headless/run_script",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "project_dir": project_dir,
                    "project_name": project_name,
                    "script_path": script_path,
                    "script_args": script_args,
                },
            )

        if action == "export_analysis":
            binary_path = self._required_string(kwargs, "binary_path")
            project_dir = self._required_string(kwargs, "project_dir")
            project_name = self._required_string(kwargs, "project_name")
            export_script = self._required_string(kwargs, "export_script")
            output_file = self._required_string(kwargs, "output_file")

            return ToolCommand(
                command=[
                    "analyzeHeadless",
                    project_dir,
                    project_name,
                    "-import",
                    binary_path,
                    "-overwrite",
                    "-postScript",
                    export_script,
                    output_file,
                ],
                action="export_analysis",
                evidence_title=f"Ghidra export analysis: {binary_path}",
                evidence_relative_dir="reverse_engineering/ghidra_headless/export_analysis",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "binary_path": binary_path,
                    "project_dir": project_dir,
                    "project_name": project_name,
                    "export_script": export_script,
                    "output_file": output_file,
                },
            )

        raise ValueError(f"Unsupported Ghidra headless action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _string_list(values: list[Any]) -> list[str]:
        """Normalize a list of string arguments."""

        return [str(value).strip() for value in values if str(value).strip()]

    @staticmethod
    def _positive_int(value: Any, key: str) -> int:
        """Validate a positive integer."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return parsed
