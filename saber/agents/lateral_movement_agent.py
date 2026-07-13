"""Lateral movement agent for SABER.

The LateralMovementAgent plans and validates movement paths after authorized
access exists. It does not execute movement directly without approval. It uses
lateral movement wrappers for planning, session checks, and dry-run validation.
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


class LateralMovementAgent(BaseAgent):
    """Plan, rank, and validate lateral movement paths."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize lateral movement agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="lateral_movement_agent",
                phase=AssessmentPhase.LATERAL_MOVEMENT,
                prompt_path="prompts/lateral_movement_agent_prompt.txt",
                description="Plans and validates lateral movement paths from evidence.",
                default_metadata={"agent_type": "lateral_movement"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next lateral movement workflow step."""

        objective = context.objective.strip() or "Plan and validate lateral movement."

        if llm_decision := self.try_llm_decision(context, objective=objective):
            return llm_decision

        if not context.observations:
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="No observations exist for lateral movement planning.",
                metadata={"reason": "missing_observations"},
            )

        if self._has_ad_graph_data(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Plan likely lateral movement paths from AD graph evidence.",
                tool_call=AgentToolCall(
                    tool_name="lateral_movement_planner",
                    action="plan_paths",
                    args={
                        "source": "current_access",
                        "destination": "high_value_assets",
                        "facts": self._observation_summaries(context.observations),
                    },
                    reason="AD graph or relationship evidence exists; plan possible paths.",
                    metadata={"workflow_step": "path_planning"},
                ),
                metadata={"workflow_step": "path_planning"},
            )

        if self._has_active_session(context.observations) and not self._has_candidate_path(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Summarize available sessions before movement planning.",
                tool_call=AgentToolCall(
                    tool_name="session_checks",
                    action="summarize_sessions",
                    args={"sessions": self._observation_summaries(context.observations)},
                    reason="A foothold/session exists; summarize sessions before selecting movement paths.",
                    metadata={"workflow_step": "session_summary"},
                ),
                metadata={"workflow_step": "session_summary"},
            )

        if self._has_candidate_path(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Validate candidate lateral movement path without executing movement.",
                tool_call=AgentToolCall(
                    tool_name="path_validation",
                    action="dry_run_path",
                    args={"path": self._observation_summaries(context.observations)},
                    reason="Candidate movement path exists; run dry validation before approval.",
                    metadata={"workflow_step": "path_dry_run"},
                ),
                metadata={"workflow_step": "path_dry_run"},
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="No usable session, path, or AD relationship evidence was found.",
            metadata={"reason": "no_lateral_evidence"},
        )

    def build_movement_approval_decision(
        self,
        path_id: str,
        reason: str,
        objective: str = "Request approval for a lateral movement step.",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval decision before any real movement action."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before lateral movement path: {path_id}",
            tool_call=AgentToolCall(
                tool_name="path_validation",
                action="validate_path",
                args={"path_id": path_id, "approval_reason": reason},
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"path_id": path_id, "approval_type": "lateral_movement", **(metadata or {})},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom lateral movement command.",
        expected_output: str | None = None,
        risk_level: str = "high",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated custom CLI decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom lateral movement command: {reason}",
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
    def _has_active_session(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention active access."""

        return any(
            LateralMovementAgent._contains_any(
                observation,
                ["session", "foothold", "shell", "authenticated access", "valid credentials", "logged in"],
            )
            for observation in observations
        )

    @staticmethod
    def _has_candidate_path(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention a candidate movement path."""

        return any(
            LateralMovementAgent._contains_any(
                observation,
                ["candidate path", "attack path", "path to", "can access", "admin to", "reachable from"],
            )
            for observation in observations
        )

    @staticmethod
    def _has_ad_graph_data(observations: list[AgentObservation]) -> bool:
        """Return whether observations mention AD graph relationship data."""

        return any(
            LateralMovementAgent._contains_any(
                observation,
                ["bloodhound", "active directory", "domain admin", "group membership", "ad relationship"],
            )
            for observation in observations
        )

    @staticmethod
    def _observation_summaries(observations: list[AgentObservation]) -> list[str]:
        """Return observation summaries."""

        return [observation.summary for observation in observations]

    @staticmethod
    def _contains_any(observation: AgentObservation, needles: list[str]) -> bool:
        """Check observation summary and metadata for any term."""

        text = f"{observation.summary} {observation.metadata}".lower()
        return any(needle in text for needle in needles)
