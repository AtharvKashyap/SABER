"""theHarvester wrapper for SABER."""

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
    tool_name="theharvester",
    category="recon",
    phase="recon",
    description="OSINT harvesting of hosts, emails, and other artifacts.",
    parser="theharvester",
    actions=(
        ActionContract(
            action="search",
            description="theHarvester OSINT search across configured sources.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec(
                    "sources",
                    "str",
                    required=False,
                    default="all",
                    description="Comma-separated OSINT source list (wrapper kwarg name).",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("host", "account", "note"),
            example_args={"domain": "example.com", "sources": "all"},
        ),
    ),
)


class TheHarvesterWrapper(BaseToolWrapper):
    """Wrapper for theHarvester OSINT reconnaissance workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize theHarvester wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="theharvester",
                image="saber/theharvester:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="TheHarvesterWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "recon", "tool": "theharvester"},
            ),
        )

    def search(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        sources: str = "bing,duckduckgo,crtsh",
        limit: int | None = None,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run theHarvester against a domain."""

        return self.run(
            target=target,
            session=session,
            action="search",
            domain=domain,
            sources=sources,
            limit=limit,
            output_file=output_file,
            metadata=metadata,
        )

    def email_search(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        sources: str = "bing,duckduckgo,crtsh",
        limit: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run theHarvester for email-focused collection."""

        return self.run(
            target=target,
            session=session,
            action="email_search",
            domain=domain,
            sources=sources,
            limit=limit,
            metadata=metadata,
        )

    def host_search(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        sources: str = "bing,duckduckgo,crtsh",
        limit: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run theHarvester for host-focused collection."""

        return self.run(
            target=target,
            session=session,
            action="host_search",
            domain=domain,
            sources=sources,
            limit=limit,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a theHarvester ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        if action not in {"search", "email_search", "host_search"}:
            raise ValueError(f"Unsupported theHarvester action: {action}")

        domain = self._domain_from_target_or_kwargs(target, kwargs)
        sources = self._required_string(kwargs, "sources")
        command = ["theHarvester", "-d", domain, "-b", sources]

        limit = kwargs.get("limit")
        if limit is not None:
            command.extend(["-l", str(self._positive_int(limit, "limit"))])

        output_file = kwargs.get("output_file")
        if output_file:
            command.extend(["-f", str(output_file)])

        if action == "email_search":
            evidence_dir = "recon/theharvester/email_search"
            title = f"theHarvester email search: {domain}"
        elif action == "host_search":
            evidence_dir = "recon/theharvester/host_search"
            title = f"theHarvester host search: {domain}"
        else:
            evidence_dir = "recon/theharvester/search"
            title = f"theHarvester search: {domain}"

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=title,
            evidence_relative_dir=evidence_dir,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "domain": domain,
                "sources": sources,
                "limit": limit,
                "output_file": output_file,
                "target": target.tool_value() if isinstance(target, Target) else None,
                **(kwargs.get("metadata") or {}),
            },
        )

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
