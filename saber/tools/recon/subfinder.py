"""Subfinder wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class SubfinderWrapper(BaseToolWrapper):
    """Wrapper for ProjectDiscovery Subfinder."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Subfinder wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="subfinder",
                image="saber/subfinder:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="SubfinderWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "recon", "tool": "subfinder"},
            ),
        )

    def enumerate(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        output_file: str | None = None,
        silent: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate subdomains for a domain."""

        return self.run(
            target=target,
            session=session,
            action="enumerate",
            domain=domain,
            output_file=output_file,
            silent=silent,
            metadata=metadata,
        )

    def enumerate_all_sources(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate subdomains using all configured sources."""

        return self.run(
            target=target,
            session=session,
            action="enumerate_all_sources",
            domain=domain,
            output_file=output_file,
            metadata=metadata,
        )

    def enumerate_from_list(
        self,
        target: Target,
        session: MissionSession,
        domain_list: str,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate subdomains for domains listed in a file."""

        return self.run(
            target=target,
            session=session,
            action="enumerate_from_list",
            domain_list=domain_list,
            output_file=output_file,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Subfinder ToolCommand."""

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

        if action in {"enumerate", "enumerate_all_sources"}:
            domain = self._domain_from_target_or_kwargs(target, kwargs)
            command = ["subfinder", "-d", domain]
            if action == "enumerate_all_sources":
                command.append("-all")
            silent = bool(kwargs.get("silent", True))
            if silent:
                command.append("-silent")
            output_file = kwargs.get("output_file")
            if output_file:
                command.extend(["-o", str(output_file)])

            relative_dir = "recon/subfinder/enumerate_all_sources" if action == "enumerate_all_sources" else "recon/subfinder/enumerate"

            return ToolCommand(
                command=command,
                action=action,
                evidence_title=f"Subfinder {action}: {domain}",
                evidence_relative_dir=relative_dir,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "domain": domain, "silent": silent, "output_file": output_file},
            )

        if action == "enumerate_from_list":
            domain_list = self._required_string(kwargs, "domain_list")
            command = ["subfinder", "-dL", domain_list]
            output_file = kwargs.get("output_file")
            if output_file:
                command.extend(["-o", str(output_file)])

            return ToolCommand(
                command=command,
                action="enumerate_from_list",
                evidence_title=f"Subfinder list enum: {domain_list}",
                evidence_relative_dir="recon/subfinder/enumerate_from_list",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "domain_list": domain_list, "output_file": output_file},
            )

        raise ValueError(f"Unsupported Subfinder action: {action}")

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
