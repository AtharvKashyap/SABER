"""Enum4linux wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class Enum4LinuxWrapper(BaseToolWrapper):
    """Wrapper for SMB enumeration with enum4linux-ng/enum4linux."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize enum4linux wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="enum4linux",
                image="saber/enum4linux:latest",
                phase=AssessmentPhase.NETWORK,
                category=RequestedActionCategory.NETWORK,
                requested_by="Enum4LinuxWrapper",
                default_timeout_seconds=600,
                default_metadata={"tool_family": "network", "tool": "enum4linux"},
            ),
        )

    def full_enum(
        self,
        target: Target,
        session: MissionSession,
        username: str | None = None,
        password: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run full SMB enumeration."""

        return self.run(
            target=target,
            session=session,
            action="full_enum",
            username=username,
            password=password,
            metadata=metadata,
        )

    def users(
        self,
        target: Target,
        session: MissionSession,
        username: str | None = None,
        password: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate SMB users."""

        return self.run(
            target=target,
            session=session,
            action="users",
            username=username,
            password=password,
            metadata=metadata,
        )

    def shares(
        self,
        target: Target,
        session: MissionSession,
        username: str | None = None,
        password: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate SMB shares."""

        return self.run(
            target=target,
            session=session,
            action="shares",
            username=username,
            password=password,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build an enum4linux ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")
        base = ["enum4linux", "-o"]

        if action == "full_enum":
            base.append("-a")
            relative_dir = "network/enum4linux/full"
        elif action == "users":
            base.append("-U")
            relative_dir = "network/enum4linux/users"
        elif action == "shares":
            base.append("-S")
            relative_dir = "network/enum4linux/shares"
        else:
            raise ValueError(f"Unsupported enum4linux action: {action}")

        username = kwargs.get("username")
        password = kwargs.get("password")
        if username:
            base.extend(["-u", str(username)])
        if password:
            base.extend(["-p", str(password)])
        base.append(destination)

        return ToolCommand(
            command=base,
            action=action,
            evidence_title=f"enum4linux {action}: {destination}",
            evidence_relative_dir=relative_dir,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "target": destination,
                "username": username,
                "password": "<redacted>" if password else None,
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
