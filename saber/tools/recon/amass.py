"""Amass wrapper for SABER."""

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
    tool_name="amass",
    category="recon",
    phase="recon",
    description="Passive subdomain/asset enumeration.",
    parser="amass",
    actions=(
        ActionContract(
            action="passive_enum",
            description="Passive enumeration (alias of `enum_passive`).",
            args=(ArgSpec("domain", "str", required=True, description="Domain in scope."),),
            risk="low",
            requires_approval=False,
            emits_kinds=("host",),
            example_args={"domain": "example.com"},
        ),
        ActionContract(
            action="enum_passive",
            description="Passive enumeration using OSINT sources only (no traffic to the target).",
            args=(ArgSpec("domain", "str", required=True, description="Domain in scope."),),
            risk="low",
            requires_approval=False,
            emits_kinds=("host",),
            example_args={"domain": "example.com"},
        ),
        ActionContract(
            action="enum_active",
            description="Active enumeration: resolves and probes the target's DNS infrastructure.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec("resolvers_file", "str", required=False, description="Custom resolver list."),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host",),
            example_args={"domain": "example.com"},
        ),
        ActionContract(
            action="intel",
            description="Collect organisation intel (whois-adjacent) to widen the attack surface.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec("whois", "bool", required=False, default=True),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("host",),
            example_args={"domain": "example.com", "whois": True},
        ),
        ActionContract(
            action="db_export",
            description="Export previously collected Amass graph data as JSON.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec(
                    "output_file",
                    "str",
                    required=True,
                    default="amass_graph.json",
                    description="Destination path for the JSON graph export.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("host",),
            example_args={"domain": "example.com", "output_file": "amass_graph.json"},
        ),
    ),
)


class AmassWrapper(BaseToolWrapper):
    """Wrapper for OWASP Amass reconnaissance workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Amass wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="amass",
                image="saber/amass:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="AmassWrapper",
                default_timeout_seconds=1800,
                default_metadata={"tool_family": "recon", "tool": "amass"},
            ),
        )

    def enum_passive(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run passive Amass enum."""

        return self.run(
            target=target,
            session=session,
            action="enum_passive",
            domain=domain,
            output_file=output_file,
            metadata=metadata,
        )

    def enum_active(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        resolvers_file: str | None = None,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run active Amass enum."""

        return self.run(
            target=target,
            session=session,
            action="enum_active",
            domain=domain,
            resolvers_file=resolvers_file,
            output_file=output_file,
            metadata=metadata,
        )

    def intel(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        whois: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Amass intel mode."""

        return self.run(
            target=target,
            session=session,
            action="intel",
            domain=domain,
            whois=whois,
            metadata=metadata,
        )

    def db_export(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        output_file: str = "amass_graph.json",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Export Amass graph data."""

        return self.run(
            target=target,
            session=session,
            action="db_export",
            domain=domain,
            output_file=output_file,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build an Amass ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        domain = self._domain_from_target_or_kwargs(target, kwargs)
        metadata = {
            "action": action,
            "domain": domain,
            "target": target.tool_value() if isinstance(target, Target) else None,
            **(kwargs.get("metadata") or {}),
        }

        if action in {"enum_passive", "passive_enum"}:
            command = ["amass", "enum", "-passive", "-d", domain]
            output_file = kwargs.get("output_file")
            if output_file:
                command.extend(["-o", str(output_file)])

            if action == "passive_enum":
                relative_dir = "recon/amass/passive_enum"
            else:
                relative_dir = "recon/amass/enum_passive"

            return ToolCommand(
                command=command,
                action=action,
                evidence_title=f"Amass passive enum: {domain}",
                evidence_relative_dir=relative_dir,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "output_file": output_file},
            )

        if action == "enum_active":
            command = ["amass", "enum", "-active", "-d", domain]
            resolvers_file = kwargs.get("resolvers_file")
            output_file = kwargs.get("output_file")
            if resolvers_file:
                command.extend(["-rf", str(resolvers_file)])
            if output_file:
                command.extend(["-o", str(output_file)])

            return ToolCommand(
                command=command,
                action="enum_active",
                evidence_title=f"Amass active enum: {domain}",
                evidence_relative_dir="recon/amass/enum_active",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "resolvers_file": resolvers_file, "output_file": output_file},
            )

        if action == "intel":
            command = ["amass", "intel", "-d", domain]
            whois = bool(kwargs.get("whois", True))
            if whois:
                command.append("-whois")

            return ToolCommand(
                command=command,
                action="intel",
                evidence_title=f"Amass intel: {domain}",
                evidence_relative_dir="recon/amass/intel",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "whois": whois},
            )

        if action == "db_export":
            output_file = self._required_string(kwargs, "output_file")
            return ToolCommand(
                command=["amass", "db", "-d", domain, "-json", output_file],
                action="db_export",
                evidence_title=f"Amass DB export: {domain}",
                evidence_relative_dir="recon/amass/db_export",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "output_file": output_file},
            )

        raise ValueError(f"Unsupported Amass action: {action}")

    @classmethod
    def _domain_from_target_or_kwargs(cls, target: Target | str | None, kwargs: dict[str, Any]) -> str:
        """Resolve domain from explicit kwarg or Target."""

        explicit = kwargs.get("domain")
        if explicit is not None:
            return cls._string_value(explicit, "domain")
        if isinstance(target, Target):
            return cls._string_value(target.tool_value(), "domain")
        return cls._required_string(kwargs, "domain")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        if key not in kwargs:
            raise ValueError(f"{key} is required")
        return cls._string_value(kwargs[key], key)

    @staticmethod
    def _string_value(value: Any, key: str) -> str:
        """Convert and validate a string-like value."""

        text = str(value).strip()
        if not text:
            raise ValueError(f"{key} is required")
        return text
