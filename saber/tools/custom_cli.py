"""Custom CLI wrapper for SABER.

This wrapper exists for cases where preconfigured tools are not enough. Agents
may request custom CLI work, but execution still goes through the same wrapper,
ToolRequest, SandboxExecutionRequest, Sandbox, and Evidence pipeline.

Every custom CLI action requires explicit authorization.
"""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

CONTRACT = ToolContract(
    tool_name="custom_cli",
    category=RequestedActionCategory.UNKNOWN.value,
    phase=AssessmentPhase.RECON.value,
    description=(
        "Explicitly authorized custom CLI execution for cases where preconfigured "
        "tools are insufficient. Every action requires explicit authorization and "
        "runs through bash in the sandbox."
    ),
    parser=None,
    actions=(
        ActionContract(
            action="run_command",
            description="Run one custom shell command through bash.",
            args=(
                ArgSpec(name="command", type="str", required=True,
                        description="Shell command to execute."),
                ArgSpec(name="reason", type="str", required=True,
                        description="Justification for running this command."),
                ArgSpec(name="expected_output", type="str", required=False,
                        description="Optional description of the expected output."),
                ArgSpec(name="risk_level", type="enum", required=False, default="medium",
                        choices=("low", "medium", "high"),
                        description="Operator-assessed risk level."),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={
                "command": "curl -sS -I http://127.0.0.1:8080/admin",
                "reason": "Confirm whether /admin responds before spending a full scan on it.",
                "expected_output": "HTTP status line and response headers.",
                "risk_level": "low",
            },
        ),
        ActionContract(
            action="run_script",
            description="Run a custom script file through bash.",
            args=(
                ArgSpec(name="script_path", type="str", required=True,
                        description="Path to the script to execute."),
                ArgSpec(name="reason", type="str", required=True,
                        description="Justification for running this script."),
                ArgSpec(name="script_args", type="list[str]", required=False,
                        description="Optional arguments passed to the script."),
                ArgSpec(name="expected_output", type="str", required=False,
                        description="Optional description of the expected output."),
                ArgSpec(name="risk_level", type="enum", required=False, default="medium",
                        choices=("low", "medium", "high"),
                        description="Operator-assessed risk level."),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={
                "script_path": "/tmp/saber/exploit.py",
                "reason": "Run the exploit script written for the confirmed deserialization bug.",
                "script_args": ["127.0.0.1", "8080"],
                "expected_output": "A shell banner or the contents of /etc/passwd.",
                "risk_level": "high",
            },
        ),
        ActionContract(
            action="run_pipeline",
            description="Run a custom shell pipeline through bash.",
            args=(
                ArgSpec(name="pipeline", type="str", required=True,
                        description="Shell pipeline to execute."),
                ArgSpec(name="reason", type="str", required=True,
                        description="Justification for running this pipeline."),
                ArgSpec(name="expected_output", type="str", required=False,
                        description="Optional description of the expected output."),
                ArgSpec(name="risk_level", type="enum", required=False, default="medium",
                        choices=("low", "medium", "high"),
                        description="Operator-assessed risk level."),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={
                "pipeline": "cat /tmp/saber/hosts.txt | sort -u | head -50",
                "reason": "Deduplicate the harvested host list before feeding it to the next scan.",
                "expected_output": "Up to 50 unique hostnames.",
                "risk_level": "low",
            },
        ),
    ),
)


class CustomCliWrapper(BaseToolWrapper):
    """Wrapper for explicitly authorized custom CLI execution."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize custom CLI wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="custom_cli",
                image="saber/custom-cli:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.UNKNOWN,
                requested_by="CustomCliWrapper",
                default_timeout_seconds=600,
                default_metadata={"tool_family": "custom", "tool": "custom_cli"},
            ),
        )

    def run_command(
        self,
        target: Target,
        session: MissionSession,
        command: str,
        reason: str,
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run one custom shell command through bash."""

        return self.run(
            target=target,
            session=session,
            action="run_command",
            command=command,
            reason=reason,
            expected_output=expected_output,
            risk_level=risk_level,
            metadata=metadata,
        )

    def run_script(
        self,
        target: Target,
        session: MissionSession,
        script_path: str,
        reason: str,
        script_args: list[str] | None = None,
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a custom script file."""

        return self.run(
            target=target,
            session=session,
            action="run_script",
            script_path=script_path,
            script_args=script_args or [],
            reason=reason,
            expected_output=expected_output,
            risk_level=risk_level,
            metadata=metadata,
        )

    def run_pipeline(
        self,
        target: Target,
        session: MissionSession,
        pipeline: str,
        reason: str,
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a custom shell pipeline through bash."""

        return self.run(
            target=target,
            session=session,
            action="run_pipeline",
            pipeline=pipeline,
            reason=reason,
            expected_output=expected_output,
            risk_level=risk_level,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a custom CLI ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        reason = self._required_string(kwargs, "reason")
        expected_output = kwargs.get("expected_output")
        risk_level = self._validate_risk_level(kwargs.get("risk_level", "medium"))

        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            "reason": reason,
            "expected_output": expected_output,
            "risk_level": risk_level,
            "custom_cli": True,
            **(kwargs.get("metadata") or {}),
        }

        if action == "run_command":
            raw_command = self._required_string(kwargs, "command")
            return ToolCommand(
                command=["bash", "-lc", raw_command],
                action="run_command",
                evidence_title="Custom CLI command",
                evidence_relative_dir="custom_cli/run_command",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                working_directory=kwargs.get("working_directory"),
                environment=kwargs.get("environment") or {},
                runner_options=kwargs.get("runner_options") or {},
                metadata={**metadata, "command": raw_command},
            )

        if action == "run_script":
            script_path = self._required_string(kwargs, "script_path")
            script_args = self._string_list(kwargs.get("script_args") or [])

            return ToolCommand(
                command=["bash", script_path, *script_args],
                action="run_script",
                evidence_title=f"Custom CLI script: {script_path}",
                evidence_relative_dir="custom_cli/run_script",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                working_directory=kwargs.get("working_directory"),
                environment=kwargs.get("environment") or {},
                runner_options=kwargs.get("runner_options") or {},
                metadata={**metadata, "script_path": script_path, "script_args": script_args},
            )

        if action == "run_pipeline":
            pipeline = self._required_string(kwargs, "pipeline")
            return ToolCommand(
                command=["bash", "-lc", pipeline],
                action="run_pipeline",
                evidence_title="Custom CLI pipeline",
                evidence_relative_dir="custom_cli/run_pipeline",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                working_directory=kwargs.get("working_directory"),
                environment=kwargs.get("environment") or {},
                runner_options=kwargs.get("runner_options") or {},
                metadata={**metadata, "pipeline": pipeline},
            )

        raise ValueError(f"Unsupported custom CLI action: {action}")

    def validate_command(self, command: ToolCommand) -> None:
        """Validate custom CLI command plans."""

        super().validate_command(command)

        if not command.requires_explicit_authorization:
            raise ValueError("Custom CLI commands must require explicit authorization.")

        if command.command[0] != "bash":
            raise ValueError("Custom CLI commands must execute through bash.")

    @staticmethod
    def _validate_risk_level(value: Any) -> str:
        """Validate custom CLI risk level."""

        risk_level = str(value).strip().lower()
        if risk_level not in {"low", "medium", "high"}:
            raise ValueError("risk_level must be one of: low, medium, high")
        return risk_level

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _string_list(values: list[Any]) -> list[str]:
        """Normalize string arguments."""

        return [str(value).strip() for value in values if str(value).strip()]
