"""Nmap wrapper for SABER."""

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
    tool_name="nmap",
    category="recon",
    phase="recon",
    description="Network discovery and service/version enumeration.",
    parser="nmap",
    actions=(
        ActionContract(
            action="service_scan",
            description="TCP connect service/version scan (-sT -sV -sC -Pn).",
            args=(ArgSpec("ports", "str", required=False, default=None, example="1-1000"),),
            risk="low",
            requires_approval=False,
            emits_kinds=("host", "service"),
            example_args={"ports": "1-1000"},
        ),
        ActionContract(
            action="vuln_scan",
            description="NSE vuln category scan. Intrusive.",
            args=(ArgSpec("ports", "str"),),
            risk="medium",
            requires_approval=True,
            emits_kinds=("vuln", "service"),
            example_args={},
        ),
        ActionContract(
            action="udp_scan",
            description="UDP service discovery. Slower and noisier than TCP.",
            args=(ArgSpec("ports", "str"),),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "service"),
            example_args={"ports": "53,161"},
        ),
        ActionContract(
            action="script_scan",
            description="Run a specific NSE script or category.",
            args=(
                ArgSpec("script", "str", required=True, description="NSE script or category"),
                ArgSpec("ports", "str"),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "service", "vuln"),
            example_args={"script": "http-title"},
        ),
    ),
)


class NmapWrapper(BaseToolWrapper):
    """Wrapper for Nmap reconnaissance workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Nmap wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="nmap",
                image="saber/nmap:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="NmapWrapper",
                default_timeout_seconds=1200,
                default_metadata={"tool_family": "recon", "tool": "nmap"},
            ),
        )

    def service_scan(
        self,
        target: Target,
        session: MissionSession,
        ports: str | None = None,
        output_prefix: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run service/version detection."""

        return self.run(
            target=target,
            session=session,
            action="service_scan",
            ports=ports,
            output_prefix=output_prefix,
            metadata=metadata,
        )

    def vuln_scan(
        self,
        target: Target,
        session: MissionSession,
        ports: str | None = None,
        output_prefix: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run NSE vuln scan."""

        return self.run(
            target=target,
            session=session,
            action="vuln_scan",
            ports=ports,
            output_prefix=output_prefix,
            metadata=metadata,
        )

    def udp_scan(
        self,
        target: Target,
        session: MissionSession,
        ports: str = "53,67,68,69,123,161,500,514",
        output_prefix: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run UDP scan."""

        return self.run(
            target=target,
            session=session,
            action="udp_scan",
            ports=ports,
            output_prefix=output_prefix,
            metadata=metadata,
        )

    def script_scan(
        self,
        target: Target,
        session: MissionSession,
        script: str,
        ports: str | None = None,
        output_prefix: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a specific NSE script or script category."""

        return self.run(
            target=target,
            session=session,
            action="script_scan",
            script=script,
            ports=ports,
            output_prefix=output_prefix,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build an Nmap ToolCommand."""

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

        if action == "service_scan":
            # Docker Desktop on macOS does not reliably allow raw socket scans.
            # -sT uses TCP connect scan and works consistently in the sandbox.
            command = ["nmap", "-sT", "-sV", "-sC", "-Pn"]
            relative_dir = "recon/nmap/service_scan"
            title = f"Nmap service scan: {destination}"

        elif action == "vuln_scan":
            command = ["nmap", "-sV", "--script", "vuln"]
            relative_dir = "recon/nmap/vuln_scan"
            title = f"Nmap vuln scan: {destination}"

        elif action == "udp_scan":
            command = ["nmap", "-sU", "-Pn"]
            relative_dir = "recon/nmap/udp_scan"
            title = f"Nmap UDP scan: {destination}"

        elif action == "script_scan":
            script = self._required_string(kwargs, "script")
            command = ["nmap", "-sV", "--script", script]
            relative_dir = "recon/nmap/script_scan"
            title = f"Nmap script scan: {destination}"
            metadata = {**metadata, "script": script}

        else:
            raise ValueError(f"Unsupported Nmap action: {action}")

        ports = kwargs.get("ports")
        if ports:
            command.extend(["-p", str(ports)])

        output_prefix = kwargs.get("output_prefix")
        if output_prefix:
            command.extend(["-oA", str(output_prefix)])

        command.append(destination)

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=title,
            evidence_relative_dir=relative_dir,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={**metadata, "ports": ports, "output_prefix": output_prefix},
        )

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
