"""Planner agent for SABER.

The PlannerAgent turns mission objectives and observations into high-level phase
handoffs. It does not execute tools directly. It decides which specialist agent
should receive the next step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    BaseAgent,
)
from saber.models.scope import AssessmentPhase


@dataclass(frozen=True)
class PhaseObjective:
    """One planned mission phase objective."""

    agent_name: str
    phase: str
    objective: str
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate phase objective basics."""

        if not self.agent_name.strip():
            raise ValueError("PhaseObjective.agent_name cannot be empty.")
        if not self.phase.strip():
            raise ValueError("PhaseObjective.phase cannot be empty.")
        if not self.objective.strip():
            raise ValueError("PhaseObjective.objective cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible phase objective."""

        return {
            "agent_name": self.agent_name,
            "phase": self.phase,
            "objective": self.objective,
            "depends_on": self.depends_on,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class MissionPlan:
    """High-level mission plan."""

    objective: str
    phases: list[PhaseObjective]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate mission plan basics."""

        if not self.objective.strip():
            raise ValueError("MissionPlan.objective cannot be empty.")
        if not self.phases:
            raise ValueError("MissionPlan.phases cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible mission plan."""

        return {
            "objective": self.objective,
            "phases": [phase.to_dict() for phase in self.phases],
            "metadata": self.metadata,
        }


class PlannerAgent(BaseAgent):
    """Create mission plans and select the next specialist agent."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize planner agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="planner_agent",
                phase=AssessmentPhase.RECON,
                prompt_path="prompts/planner_agent_prompt.txt",
                description="Creates SABER mission plans and phase handoffs.",
                default_metadata={"agent_type": "planner"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next high-level phase handoff."""

        objective = context.objective.strip() or "Plan SABER assessment execution."
        mission_plan = self.build_mission_plan(objective=objective, observations=context.observations)

        next_agent = self.select_next_agent(context)
        if next_agent is None:
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="Mission planning found no next agent to run.",
                metadata={"reason": "no_next_agent", "mission_plan": mission_plan.to_dict()},
            )

        return AgentDecision(
            action_type=AgentActionType.HANDOFF,
            objective=objective,
            handoff_agent=next_agent,
            message=f"Planner selected {next_agent} as the next agent.",
            metadata={"mission_plan": mission_plan.to_dict(), "selected_agent": next_agent},
        )

    def build_mission_plan(
        self,
        objective: str,
        observations: list[AgentObservation] | None = None,
    ) -> MissionPlan:
        """Build a default evidence-driven mission plan."""

        observations = observations or []
        phases = [
            PhaseObjective(
                agent_name="recon_agent",
                phase="recon",
                objective="Discover live targets, exposed services, domains, and initial attack surface.",
            ),
            PhaseObjective(
                agent_name="network_agent",
                phase="network",
                objective="Enumerate network services and infrastructure weaknesses.",
                depends_on=["recon_agent"],
            ),
            PhaseObjective(
                agent_name="web_agent",
                phase="web",
                objective="Test discovered web applications for exposure and common vulnerabilities.",
                depends_on=["recon_agent"],
            ),
            PhaseObjective(
                agent_name="exploit_agent",
                phase="exploitation",
                objective="Research and safely validate exploitability from confirmed evidence.",
                depends_on=["recon_agent", "network_agent", "web_agent"],
            ),
            PhaseObjective(
                agent_name="post_exploit_agent",
                phase="post_exploitation",
                objective="Enumerate host context after authorized access exists.",
                depends_on=["exploit_agent"],
            ),
            PhaseObjective(
                agent_name="lateral_movement_agent",
                phase="lateral_movement",
                objective="Plan and validate lateral movement paths only after authorized access exists.",
                depends_on=["post_exploit_agent"],
            ),
            PhaseObjective(
                agent_name="reporter_agent",
                phase="reporting",
                objective="Generate evidence-backed executive and technical reporting.",
                depends_on=["recon_agent"],
            ),
        ]

        if self._mentions_binary_analysis(objective, observations):
            phases.insert(
                1,
                PhaseObjective(
                    agent_name="reverse_engineer_agent",
                    phase="reverse_engineering",
                    objective="Analyze binaries, protections, strings, functions, and exploitability signals.",
                    depends_on=["recon_agent"],
                ),
            )

        return MissionPlan(
            objective=objective,
            phases=phases,
            metadata={"observation_count": len(observations)},
        )

    def select_next_agent(self, context: AgentContext) -> str | None:
        """Select the next specialist agent from objective and observations."""

        text = self._context_text(context)

        if self._contains_any(text, ["report", "writeup", "executive summary", "final deliverable"]):
            return "reporter_agent"

        if self._contains_any(text, ["shell", "session", "foothold", "meterpreter", "authenticated access"]):
            return "post_exploit_agent"

        if self._contains_any(text, ["lateral", "attack path", "bloodhound path", "domain admin path"]):
            return "lateral_movement_agent"

        if self._contains_any(text, ["cve", "exploit", "vulnerable", "rce", "sqli", "sql injection"]):
            return "exploit_agent"

        if self._contains_any(text, ["binary", "elf", "pe32", "reverse engineer", "checksec", "ghidra", "radare2"]):
            return "reverse_engineer_agent"

        if self._contains_any(text, ["http", "https", "web", "nginx", "apache", "iis", "wordpress"]):
            return "web_agent"

        if self._contains_any(text, ["smb", "snmp", "ldap", "rdp", "ssh", "network", "port 445", "port 161"]):
            return "network_agent"

        if not context.observations:
            return "recon_agent"

        return "recon_agent"

    @staticmethod
    def _mentions_binary_analysis(objective: str, observations: list[AgentObservation]) -> bool:
        """Return whether objective or observations suggest binary analysis."""

        text = f"{objective} " + " ".join(f"{obs.summary} {obs.metadata}" for obs in observations)
        return PlannerAgent._contains_any(
            text.lower(),
            ["binary", "elf", "pe32", "reverse engineer", "checksec", "ghidra", "radare2"],
        )

    @staticmethod
    def _context_text(context: AgentContext) -> str:
        """Flatten context into searchable text."""

        observations = " ".join(f"{obs.summary} {obs.metadata}" for obs in context.observations)
        return f"{context.objective} {observations}".lower()

    @staticmethod
    def _contains_any(text: str, needles: list[str]) -> bool:
        """Return whether text contains any needle."""

        return any(needle in text for needle in needles)
