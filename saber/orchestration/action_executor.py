"""Execute a ProposedAction through an existing capability agent.

The decider has already chosen the action. This dispatches it to the agent that
owns the capability and runs it via BaseAgent.execute_tool -> ToolRegistry ->
Sandbox. It never calls agent.decide() — the loop, not the agent, decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saber.agents.base_agent import AgentContext, AgentObservation, AgentToolCall, BaseAgent
from saber.agents.deciders.base import ProposedAction
from saber.models.mission_state import MissionState
from saber.models.session import MissionSession


@dataclass(frozen=True)
class ActionExecutionRecord:
    """Outcome of executing one action."""

    sandbox_result: Any
    observation: AgentObservation
    error: str | None = None


class ActionExecutor:
    """Dispatch proposed actions to capability agents."""

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: Any,
        sandbox: Any,
        default_agent: str = "recon_agent",
    ) -> None:
        """Initialize executor."""

        if not agents:
            raise ValueError("ActionExecutor requires at least one agent.")
        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox
        self.default_agent = default_agent

    def execute(
        self,
        state: MissionState,
        session: MissionSession,
        action: ProposedAction,
    ) -> ActionExecutionRecord:
        """Run one tool action and return its record."""

        agent = self._resolve_agent(action)
        target = action.target or state.target

        context = AgentContext(
            session=session,
            target=target,
            sandbox=self.sandbox,
            tool_registry=self.tool_registry,
            objective=action.objective,
            phase=agent.config.phase,
            observations=[],
            constraints={"agent_mode": "loop"},
            metadata={"proposed_action": action.to_dict()},
        )

        tool_call = AgentToolCall(
            tool_name=action.tool_name or "",
            action=action.tool_action or "",
            args=action.args,
            reason=action.rationale,
            metadata={"category": action.metadata.get("category", "")},
        )

        try:
            sandbox_result = agent.execute_tool(context=context, tool_call=tool_call)
        except Exception as exc:  # noqa: BLE001 - loop must survive tool failures
            observation = AgentObservation(
                summary=f"Action {action.tool_name}.{action.tool_action} failed: {exc}",
                tool_name=action.tool_name,
                action=action.tool_action,
                success=False,
            )
            return ActionExecutionRecord(
                sandbox_result=None, observation=observation, error=str(exc)
            )

        success = bool(getattr(sandbox_result, "allowed", True)) and (
            getattr(sandbox_result, "return_code", 0) == 0
        )
        observation = AgentObservation(
            summary=getattr(sandbox_result, "reason", None) or "Tool execution completed.",
            tool_name=action.tool_name,
            action=action.tool_action,
            success=success,
            result=sandbox_result,
            metadata=getattr(sandbox_result, "metadata", {}) or {},
        )
        return ActionExecutionRecord(
            sandbox_result=sandbox_result, observation=observation, error=None
        )

    def _resolve_agent(self, action: ProposedAction) -> BaseAgent:
        if action.agent_name and action.agent_name in self.agents:
            return self.agents[action.agent_name]
        if self.default_agent in self.agents:
            return self.agents[self.default_agent]
        return next(iter(self.agents.values()))
