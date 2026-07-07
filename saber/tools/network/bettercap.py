"""Bettercap wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class BettercapWrapper(BaseToolWrapper):
    """Wrapper for Bettercap network discovery/capture commands."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Bettercap wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="bettercap",
                image="saber/bettercap:latest",
                phase=AssessmentPhase.NETWORK,
                category=RequestedActionCategory.NETWORK,
                requested_by="BettercapWrapper",
                default_timeout_seconds=600,
                default_metadata={"tool_family": "network", "tool": "bettercap"},
            ),
        )

    def net_probe(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Bettercap network probe."""

        return self.run(target=target, session=session, action="net_probe", interface=interface, metadata=metadata)

    def net_recon(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Bettercap network recon."""

        return self.run(target=target, session=session, action="net_recon", interface=interface, metadata=metadata)

    def caplet(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        caplet_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Bettercap caplet."""

        return self.run(
            target=target,
            session=session,
            action="caplet",
            interface=interface,
            caplet_path=caplet_path,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Bettercap ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        interface = self._required_string(kwargs, "interface")

        if action == "net_probe":
            command = ["bettercap", "-iface", interface, "-eval", "net.probe on; sleep 10; net.show; quit"]
            relative_dir = "network/bettercap/net_probe"
            evidence_title = f"Bettercap net probe: {interface}"
            requires_auth = False
        elif action == "net_recon":
            command = ["bettercap", "-iface", interface, "-eval", "net.recon on; sleep 10; net.show; quit"]
            relative_dir = "network/bettercap/net_recon"
            evidence_title = f"Bettercap net recon: {interface}"
            requires_auth = False
        elif action == "caplet":
            caplet_path = self._required_string(kwargs, "caplet_path")
            command = ["bettercap", "-iface", interface, "-caplet", caplet_path]
            relative_dir = "network/bettercap/caplet"
            evidence_title = f"Bettercap caplet: {caplet_path}"
            requires_auth = True
        else:
            raise ValueError(f"Unsupported Bettercap action: {action}")

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=evidence_title,
            evidence_relative_dir=relative_dir,
            requires_explicit_authorization=requires_auth,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "interface": interface,
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
