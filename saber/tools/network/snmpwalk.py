"""SNMPWalk wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class SnmpwalkWrapper(BaseToolWrapper):
    """Wrapper for SNMP enumeration with snmpwalk."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize SNMPWalk wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="snmpwalk",
                image="saber/snmpwalk:latest",
                phase=AssessmentPhase.NETWORK,
                category=RequestedActionCategory.NETWORK,
                requested_by="SnmpwalkWrapper",
                default_timeout_seconds=300,
                default_metadata={"tool_family": "network", "tool": "snmpwalk"},
            ),
        )

    def walk(
        self,
        target: Target,
        session: MissionSession,
        community: str = "public",
        oid: str = "1.3.6.1.2.1",
        version: str = "2c",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run SNMP walk against a target."""

        return self.run(
            target=target,
            session=session,
            action="walk",
            community=community,
            oid=oid,
            version=version,
            metadata=metadata,
        )

    def system_info(
        self,
        target: Target,
        session: MissionSession,
        community: str = "public",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate SNMP system information."""

        return self.walk(
            target=target,
            session=session,
            community=community,
            oid="1.3.6.1.2.1.1",
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build an SNMPWalk ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")
        if action != "walk":
            raise ValueError(f"Unsupported SNMPWalk action: {action}")

        destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")
        community = self._required_string(kwargs, "community")
        oid = self._required_string(kwargs, "oid")
        version = self._required_string(kwargs, "version")

        return ToolCommand(
            command=["snmpwalk", "-v", version, "-c", community, destination, oid],
            action="walk",
            evidence_title=f"SNMP walk: {destination}",
            evidence_relative_dir="network/snmpwalk",
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "target": destination,
                "community": community,
                "oid": oid,
                "version": version,
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
