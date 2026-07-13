"""Network agent for SABER.

The NetworkAgent owns service and infrastructure enumeration decisions. It does
not run commands directly. It selects network wrappers through the registry and
delegates execution through Sandbox.
"""

from __future__ import annotations

from typing import Any

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    AgentToolCall,
    BaseAgent,
)
from saber.models.scope import AssessmentPhase


class NetworkAgent(BaseAgent):
    """Plan and execute network/service enumeration steps."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize network agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="network_agent",
                phase=AssessmentPhase.NETWORK,
                prompt_path="prompts/network_agent_prompt.txt",
                description="Enumerates network services and infrastructure evidence.",
                default_metadata={"agent_type": "network"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next network enumeration step."""

        objective = context.objective.strip() or "Enumerate network services."

        if llm_decision := self.try_llm_decision(context, objective=objective):
            return llm_decision

        if self._mentions_smb(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Enumerate SMB shares and service information.",
                tool_call=AgentToolCall(
                    tool_name="enum4linux",
                    action="shares",
                    args={},
                    reason="SMB exposure was observed; enumerate shares before deeper authenticated checks.",
                    metadata={"workflow_step": "smb_enum"},
                ),
                metadata={"workflow_step": "smb_enum"},
            )

        if self._mentions_snmp(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Enumerate SNMP system information.",
                tool_call=AgentToolCall(
                    tool_name="snmpwalk",
                    action="walk",
                    args={"community": "public", "oid": "1.3.6.1.2.1", "version": "2c"},
                    reason="SNMP exposure was observed; run baseline SNMP walk.",
                    metadata={"workflow_step": "snmp_enum"},
                ),
                metadata={"workflow_step": "snmp_enum"},
            )

        if self._needs_vulnerability_scan(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Create an OpenVAS target for infrastructure vulnerability scanning.",
                tool_call=AgentToolCall(
                    tool_name="openvas",
                    action="create_target",
                    args={"name": "saber-target", "hosts": context.target.tool_value()},
                    reason="Network services were discovered; prepare OpenVAS scan target.",
                    metadata={"workflow_step": "openvas_target"},
                ),
                metadata={"workflow_step": "openvas_target"},
            )

        if not context.observations:
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=objective,
                handoff_agent="recon_agent",
                message="No network observations exist yet. Start with recon/service discovery.",
                metadata={"reason": "missing_network_observations"},
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="No network-specific action was selected from current observations.",
            metadata={"reason": "no_network_action"},
        )

    def build_responder_approval_decision(
        self,
        interface: str,
        reason: str,
        objective: str = "Request approval for Responder capture workflow.",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval decision for Responder-like capture activity."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before Responder listener on interface {interface}.",
            tool_call=AgentToolCall(
                tool_name="responder",
                action="listen",
                args={"interface": interface},
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"interface": interface, "approval_type": "responder", **(metadata or {})},
        )

    def build_bettercap_approval_decision(
        self,
        interface: str,
        reason: str,
        objective: str = "Request approval for Bettercap network action.",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval decision for Bettercap workflow."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before Bettercap action on interface {interface}.",
            tool_call=AgentToolCall(
                tool_name="bettercap",
                action="net_recon",
                args={"interface": interface},
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"interface": interface, "approval_type": "bettercap", **(metadata or {})},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom network command.",
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated custom CLI decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom network command: {reason}",
            tool_call=AgentToolCall(
                tool_name="custom_cli",
                action="run_command",
                args={
                    "command": command,
                    "reason": reason,
                    "expected_output": expected_output,
                    "risk_level": risk_level,
                },
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"custom_cli": True, **(metadata or {})},
        )

    @staticmethod
    def _mentions_smb(context: AgentContext) -> bool:
        """Return whether context mentions SMB."""

        return NetworkAgent._context_contains(context, ["smb", "port 445", "netbios", "windows file sharing"])

    @staticmethod
    def _mentions_snmp(context: AgentContext) -> bool:
        """Return whether context mentions SNMP."""

        return NetworkAgent._context_contains(context, ["snmp", "port 161", "udp/161"])

    @staticmethod
    def _needs_vulnerability_scan(context: AgentContext) -> bool:
        """Return whether context explicitly requests OpenVAS/GVM workflow.

        Do not trigger OpenVAS just because many services exist. OpenVAS depends
        on an external scanner service and should only run when explicitly asked.
        """

        return NetworkAgent._context_contains(context, ["openvas", "gvm", "greenbone"])

    @staticmethod
    def _context_contains(context: AgentContext, needles: list[str]) -> bool:
        """Check objective and observations for terms."""

        observations = " ".join(f"{obs.summary} {obs.metadata}" for obs in context.observations)
        text = f"{context.objective} {observations}".lower()
        return any(needle in text for needle in needles)
