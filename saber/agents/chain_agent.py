"""Chain agent for SABER.

The ChainAgent coordinates multi-step attack chains across phases. It does not
run shell commands directly. It evaluates prior observations and decides whether
to stop, hand off to a phase agent, request approval, or execute a registry tool.
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


class ChainAgent(BaseAgent):
    """Coordinate multi-step evidence-backed chains."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize chain agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="chain_agent",
                phase=AssessmentPhase.EXPLOITATION,
                prompt_path="prompts/chain_agent_prompt.txt",
                description="Coordinates multi-step attack chains across SABER agents.",
                default_metadata={"agent_type": "chain"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next chain step from context and observations."""

        objective = context.objective.strip() or "Coordinate the next evidence-backed chain step."

        if not context.observations:
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=objective,
                handoff_agent="recon_agent",
                message="No observations exist yet. Start with reconnaissance before building chains.",
                metadata={"reason": "missing_observations"},
            )

        if self._has_confirmed_foothold(context.observations):
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=objective,
                handoff_agent="post_exploit_agent",
                message="A foothold was observed. Hand off to post-exploitation enumeration.",
                metadata={"reason": "confirmed_foothold"},
            )

        if self._has_web_surface(context.observations):
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=objective,
                handoff_agent="web_agent",
                message="Web surface was observed. Hand off to web testing.",
                metadata={"reason": "web_surface_observed"},
            )

        if self._has_possible_vulnerability(context.observations):
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=objective,
                handoff_agent="exploit_agent",
                message="Possible vulnerability evidence exists. Hand off to exploit validation.",
                metadata={"reason": "possible_vulnerability"},
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="No actionable chain step found from current observations.",
            metadata={"reason": "no_actionable_chain"},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom chain command.",
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build an approval-gated custom CLI decision for unusual chain steps."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom chain command: {reason}",
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
    def _has_web_surface(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention web surface."""

        return any(
            ChainAgent._contains_any(
                observation,
                ["http", "https", "web", "port 80", "port 443", "nginx", "apache", "iis"],
            )
            for observation in observations
        )

    @staticmethod
    def _has_possible_vulnerability(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention possible vulnerability evidence."""

        return any(
            ChainAgent._contains_any(
                observation,
                ["cve", "vulnerable", "exploit", "outdated", "critical", "high severity"],
            )
            for observation in observations
        )

    @staticmethod
    def _has_confirmed_foothold(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention confirmed access."""

        return any(
            ChainAgent._contains_any(
                observation,
                ["shell", "session", "foothold", "meterpreter", "authenticated access", "remote code execution confirmed"],
            )
            for observation in observations
        )

    @staticmethod
    def _contains_any(observation: AgentObservation, needles: list[str]) -> bool:
        """Check summary and metadata text for any term."""

        text = f"{observation.summary} {observation.metadata}".lower()
        return any(needle in text for needle in needles)
