"""Recon agent for SABER.

The ReconAgent owns initial discovery decisions: host/service discovery, domain
and subdomain enumeration, DNS enumeration, OSINT harvesting, and web
fingerprinting handoff decisions.
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
from saber.models.target import TargetType


class ReconAgent(BaseAgent):
    """Plan and execute reconnaissance decisions."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize recon agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="recon_agent",
                phase=AssessmentPhase.RECON,
                prompt_path="prompts/recon_agent_prompt.txt",
                description="Discovers hosts, services, domains, subdomains, and initial attack surface.",
                default_metadata={"agent_type": "recon"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next reconnaissance step."""

        objective = context.objective.strip() or "Perform initial reconnaissance."

        if self._is_complete(context):
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="Reconnaissance objective is already complete.",
                metadata={"reason": "recon_complete"},
            )

        if self._has_web_surface(context.observations):
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective="Hand off discovered web surface.",
                handoff_agent="web_agent",
                message="Recon discovered web surface. Hand off to WebAgent.",
                metadata={"reason": "web_surface_discovered"},
            )

        if self._needs_subdomain_enum(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Discover subdomains for the target domain.",
                tool_call=AgentToolCall(
                    tool_name="subfinder",
                    action="passive",
                    args={"domain": context.target.tool_value()},
                    reason="Domain target or objective suggests subdomain discovery.",
                    metadata={"workflow_step": "subdomain_discovery"},
                ),
                metadata={"workflow_step": "subdomain_discovery"},
            )

        if self._needs_dns_enum(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Enumerate DNS records for the target.",
                tool_call=AgentToolCall(
                    tool_name="dnsrecon",
                    action="standard",
                    args={"domain": context.target.tool_value()},
                    reason="DNS objective or domain evidence exists.",
                    metadata={"workflow_step": "dns_enumeration"},
                ),
                metadata={"workflow_step": "dns_enumeration"},
            )

        if self._needs_osint(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run OSINT harvesting for emails, hosts, and public references.",
                tool_call=AgentToolCall(
                    tool_name="theharvester",
                    action="search",
                    args={"domain": context.target.tool_value(), "source": "all"},
                    reason="Objective asks for OSINT harvesting.",
                    metadata={"workflow_step": "osint_harvesting"},
                ),
                metadata={"workflow_step": "osint_harvesting"},
            )

        if self._needs_fast_port_discovery(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run fast port discovery.",
                tool_call=AgentToolCall(
                    tool_name="masscan",
                    action="top_ports",
                    args={"ports": "1-1000", "rate": 1000},
                    reason="Objective asks for broad or fast port discovery.",
                    metadata={"workflow_step": "fast_port_discovery"},
                ),
                metadata={"workflow_step": "fast_port_discovery"},
            )

        return AgentDecision(
            action_type=AgentActionType.TOOL,
            objective="Run baseline service discovery.",
            tool_call=AgentToolCall(
                tool_name="nmap",
                action="service_scan",
                args={"ports": "1-1000"},
                reason="Default recon step is baseline TCP service enumeration.",
                metadata={"workflow_step": "service_discovery"},
            ),
            metadata={"workflow_step": "service_discovery"},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom recon command.",
        expected_output: str | None = None,
        risk_level: str = "low",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated custom CLI decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom recon command: {reason}",
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
    def _is_complete(context: AgentContext) -> bool:
        """Return whether context says recon is complete."""

        return ReconAgent._context_contains(context, ["recon complete", "discovery complete", "no further recon"])

    @staticmethod
    def _needs_subdomain_enum(context: AgentContext) -> bool:
        """Return whether subdomain enumeration is appropriate."""

        if context.target.type == TargetType.DOMAIN:
            return True
        return ReconAgent._context_contains(context, ["subdomain", "subdomains", "domain discovery"])

    @staticmethod
    def _needs_dns_enum(context: AgentContext) -> bool:
        """Return whether DNS enumeration is appropriate."""

        return ReconAgent._context_contains(context, ["dns", "zone", "mx record", "txt record", "nameserver"])

    @staticmethod
    def _needs_osint(context: AgentContext) -> bool:
        """Return whether OSINT harvesting is appropriate."""

        return ReconAgent._context_contains(context, ["osint", "email harvest", "emails", "public sources", "theharvester"])

    @staticmethod
    def _needs_fast_port_discovery(context: AgentContext) -> bool:
        """Return whether fast port discovery is appropriate."""

        return ReconAgent._context_contains(context, ["fast scan", "wide scan", "many hosts", "large range", "masscan"])

    @staticmethod
    def _has_web_surface(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention web surface."""

        return any(
            ReconAgent._contains_any(
                observation,
                ["http", "https", "web", "port 80", "port 443", "nginx", "apache", "iis"],
            )
            for observation in observations
        )

    @staticmethod
    def _context_contains(context: AgentContext, needles: list[str]) -> bool:
        """Check objective and observations for terms."""

        observations = " ".join(f"{obs.summary} {obs.metadata}" for obs in context.observations)
        text = f"{context.objective} {observations}".lower()
        return any(needle in text for needle in needles)

    @staticmethod
    def _contains_any(observation: AgentObservation, needles: list[str]) -> bool:
        """Check observation summary and metadata for terms."""

        text = f"{observation.summary} {observation.metadata}".lower()
        return any(needle in text for needle in needles)
