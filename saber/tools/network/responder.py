"""Responder wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class ResponderWrapper(BaseToolWrapper):
    """Wrapper for Responder capture/listener workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Responder wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="responder",
                image="saber/responder:latest",
                phase=AssessmentPhase.NETWORK,
                category=RequestedActionCategory.NETWORK,
                requested_by="ResponderWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "network", "tool": "responder"},
            ),
        )

    def listen(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        analyze_only: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Start Responder listener/analyze mode."""

        return self.run(
            target=target,
            session=session,
            action="listen",
            interface=interface,
            analyze_only=analyze_only,
            metadata=metadata,
        )

    def analyze(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Responder analyze mode."""

        return self.listen(
            target=target,
            session=session,
            interface=interface,
            analyze_only=True,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Responder ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")
        if action != "listen":
            raise ValueError(f"Unsupported Responder action: {action}")

        interface = self._required_string(kwargs, "interface")
        command = ["responder", "-I", interface]
        analyze_only = bool(kwargs.get("analyze_only", True))
        if analyze_only:
            command.append("-A")

        return ToolCommand(
            command=command,
            action="listen",
            evidence_title=f"Responder listener: {interface}",
            evidence_relative_dir="network/responder/listen",
            requires_explicit_authorization=not analyze_only,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "interface": interface,
                "analyze_only": analyze_only,
                "target": target.tool_value() if isinstance(target, Target) else None,
                **(kwargs.get("metadata") or {}),
            },
        )

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
