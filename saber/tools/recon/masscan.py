"""Masscan wrapper for SABER."""

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
    tool_name="masscan",
    category="recon",
    phase="recon",
    description="High-speed port discovery.",
    parser="masscan",
    actions=(
        ActionContract(
            action="scan_ports",
            description="Masscan port scan (wrapper's real dispatch name; `top_ports` "
            "is a higher-level convenience method that calls this action).",
            args=(
                ArgSpec("ports", "str", required=True, example="80,443,445,3389,22"),
                ArgSpec("rate", "int", required=False, default=1000),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "service"),
            example_args={"ports": "80,443,445,3389,22", "rate": 1000},
        ),
        ActionContract(
            action="exclude_file_scan",
            description="Masscan port scan that skips every address listed in an exclude file.",
            args=(
                ArgSpec("ports", "str", required=True, example="80,443,445,3389,22"),
                ArgSpec(
                    "exclude_file",
                    "str",
                    required=True,
                    description="Path to a masscan --excludefile of out-of-scope addresses.",
                ),
                ArgSpec("rate", "int", required=False, default=1000),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "service"),
            example_args={"ports": "80,443", "exclude_file": "/tmp/exclude.txt", "rate": 1000},
        ),
    ),
)


class MasscanWrapper(BaseToolWrapper):
    """Wrapper for Masscan high-speed port discovery."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Masscan wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="masscan",
                image="saber/masscan:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="MasscanWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "recon", "tool": "masscan"},
            ),
        )

    def scan_ports(
        self,
        target: Target,
        session: MissionSession,
        ports: str,
        rate: int = 1000,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Masscan port scan."""

        return self.run(
            target=target,
            session=session,
            action="scan_ports",
            ports=ports,
            rate=rate,
            output_file=output_file,
            metadata=metadata,
        )

    def top_ports(
        self,
        target: Target,
        session: MissionSession,
        ports: str = "80,443,445,3389,22",
        rate: int = 1000,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Masscan scan for common ports."""

        return self.scan_ports(
            target=target,
            session=session,
            ports=ports,
            rate=rate,
            metadata=metadata,
        )

    def exclude_file_scan(
        self,
        target: Target,
        session: MissionSession,
        ports: str,
        exclude_file: str,
        rate: int = 1000,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Masscan with an exclude file."""

        return self.run(
            target=target,
            session=session,
            action="exclude_file_scan",
            ports=ports,
            exclude_file=exclude_file,
            rate=rate,
            output_file=output_file,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Masscan ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")
        metadata = {
            "action": action,
            "target": destination,
            **(kwargs.get("metadata") or {}),
        }

        if action in {"scan_ports", "exclude_file_scan"}:
            ports = self._required_string(kwargs, "ports")
            rate = self._positive_int(kwargs.get("rate", 1000), "rate")
            command = ["masscan", destination, "-p", ports, "--rate", str(rate)]

            exclude_file = kwargs.get("exclude_file")
            if action == "exclude_file_scan":
                exclude_file = self._required_string(kwargs, "exclude_file")
                command.extend(["--excludefile", exclude_file])

            output_file = kwargs.get("output_file")
            if output_file:
                command.extend(["-oJ", str(output_file)])

            relative_dir = "recon/masscan/exclude_file_scan" if action == "exclude_file_scan" else "recon/masscan/scan_ports"

            return ToolCommand(
                command=command,
                action=action,
                evidence_title=f"Masscan {action}: {destination}",
                evidence_relative_dir=relative_dir,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "ports": ports,
                    "rate": rate,
                    "exclude_file": exclude_file,
                    "output_file": output_file,
                },
            )

        raise ValueError(f"Unsupported Masscan action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

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
