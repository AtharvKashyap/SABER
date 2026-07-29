"""SNMPWalk wrapper for SABER."""

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
    tool_name="snmpwalk",
    category="network",
    phase="network",
    description="SNMP MIB enumeration: system info, running processes, and installed software.",
    parser="snmpwalk",
    actions=(
        ActionContract(
            action="enumerate",
            description=(
                "Walk an SNMP MIB subtree against a target to enumerate system "
                "information, users, running processes, and installed software."
            ),
            args=(
                ArgSpec(
                    "community",
                    "str",
                    required=False,
                    default="public",
                    description="SNMP community string.",
                    example="public",
                ),
                ArgSpec(
                    "oid",
                    "str",
                    required=False,
                    default="1.3.6.1.2.1",
                    description="Base OID to walk (default: MIB-2 system subtree).",
                    example="1.3.6.1.2.1",
                ),
                ArgSpec(
                    "version",
                    "str",
                    required=False,
                    default="2c",
                    description="SNMP protocol version.",
                    choices=("1", "2c", "3"),
                    example="2c",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("note", "account"),
            example_args={"community": "public"},
        ),
    ),
)


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

    def enumerate(
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
            action="enumerate",
            community=community,
            oid=oid,
            version=version,
            metadata=metadata,
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
        """Run SNMP walk against a target (original name; delegates to enumerate)."""

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

        return self.enumerate(
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
        # "walk" is the original dispatch name and is still used by
        # network_agent/tool_selection_agent; "enumerate" is the name the
        # CONTRACT advertises. Both build an identical command.
        if action not in ("enumerate", "walk"):
            raise ValueError(f"Unsupported SNMPWalk action: {action}")

        destination = (
            target.tool_value()
            if isinstance(target, Target)
            else self._required_string(kwargs, "destination")
        )
        community = str(kwargs.get("community") or "public").strip() or "public"
        oid = str(kwargs.get("oid") or "1.3.6.1.2.1").strip() or "1.3.6.1.2.1"
        version = str(kwargs.get("version") or "2c").strip() or "2c"

        return ToolCommand(
            command=["snmpwalk", "-v", version, "-c", community, destination, oid],
            action=action,
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
