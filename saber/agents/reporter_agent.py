"""Reporter agent for SABER.

The ReporterAgent converts observations, findings, and execution metadata into
report sections. It does not scan or exploit. It consumes evidence produced by
other agents and prepares structured reporting output.
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
class ReportSection:
    """One structured report section."""

    title: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate section basics."""

        if not self.title.strip():
            raise ValueError("ReportSection.title cannot be empty.")
        if not self.content.strip():
            raise ValueError("ReportSection.content cannot be empty.")

    def to_markdown(self) -> str:
        """Render section as Markdown."""

        return f"## {self.title}\n\n{self.content.strip()}\n"

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible section."""

        return {
            "title": self.title,
            "content": self.content,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ReportDraft:
    """Structured report draft."""

    title: str
    sections: list[ReportSection]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate draft basics."""

        if not self.title.strip():
            raise ValueError("ReportDraft.title cannot be empty.")
        if not self.sections:
            raise ValueError("ReportDraft.sections cannot be empty.")

    def to_markdown(self) -> str:
        """Render full report draft as Markdown."""

        section_text = "\n".join(section.to_markdown() for section in self.sections)
        return f"# {self.title}\n\n{section_text}".rstrip() + "\n"

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible report draft."""

        return {
            "title": self.title,
            "sections": [section.to_dict() for section in self.sections],
            "metadata": self.metadata,
        }


class ReporterAgent(BaseAgent):
    """Generate evidence-backed report drafts from observations."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize reporter agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="reporter_agent",
                phase=AssessmentPhase.REPORTING,
                prompt_path="prompts/reporter_agent_prompt.txt",
                description="Builds executive and technical reports from evidence.",
                default_metadata={"agent_type": "reporter"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide reporting outcome from current evidence."""

        objective = context.objective.strip() or "Generate SABER assessment report."

        if not context.observations:
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="No observations are available for reporting.",
                metadata={"reason": "missing_report_evidence"},
            )

        draft = self.build_report_draft(context)

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="Report draft generated from current observations.",
            metadata={
                "reason": "report_generated",
                "report": draft.to_dict(),
                "markdown": draft.to_markdown(),
            },
        )

    def build_report_draft(self, context: AgentContext) -> ReportDraft:
        """Build a structured report draft from context observations."""

        sections = [
            self._build_executive_summary(context),
            self._build_scope_summary(context),
            self._build_technical_findings(context),
            self._build_timeline(context),
            self._build_recommendations(context),
        ]

        return ReportDraft(
            title=f"SABER Assessment Report - {context.target.tool_value()}",
            sections=sections,
            metadata={
                "target": context.target.tool_value(),
                "session_id": context.session.session_id,
                "observation_count": len(context.observations),
            },
        )

    def _build_executive_summary(self, context: AgentContext) -> ReportSection:
        """Build executive summary section."""

        high_signal = self._summarize_high_signal_observations(context.observations)

        return ReportSection(
            title="Executive Summary",
            content=(
                f"SABER assessed `{context.target.tool_value()}` and collected "
                f"{len(context.observations)} observation(s). "
                f"{high_signal}"
            ),
            metadata={"section_type": "executive_summary"},
        )

    def _build_scope_summary(self, context: AgentContext) -> ReportSection:
        """Build scope summary section."""

        return ReportSection(
            title="Scope and Objective",
            content=(
                f"Target: `{context.target.tool_value()}`\n\n"
                f"Objective: {context.objective or 'No objective provided.'}"
            ),
            metadata={"section_type": "scope"},
        )

    def _build_technical_findings(self, context: AgentContext) -> ReportSection:
        """Build technical findings section."""

        lines = []
        for index, observation in enumerate(context.observations, start=1):
            tool_prefix = ""
            if observation.tool_name:
                tool_prefix = f" **[{observation.tool_name}:{observation.action or 'unknown'}]**"
            status = "success" if observation.success else "failed"
            lines.append(f"{index}. ({status}){tool_prefix} {observation.summary}")

        return ReportSection(
            title="Technical Findings and Observations",
            content="\n".join(lines),
            metadata={"section_type": "technical_findings"},
        )

    def _build_timeline(self, context: AgentContext) -> ReportSection:
        """Build simple timeline section."""

        lines = []
        for index, observation in enumerate(context.observations, start=1):
            lines.append(f"{index}. {observation.summary}")

        return ReportSection(
            title="Assessment Timeline",
            content="\n".join(lines),
            metadata={"section_type": "timeline"},
        )

    def _build_recommendations(self, context: AgentContext) -> ReportSection:
        """Build recommendation section."""

        recommendations = self._derive_recommendations(context.observations)

        return ReportSection(
            title="Recommendations",
            content="\n".join(f"- {item}" for item in recommendations),
            metadata={"section_type": "recommendations"},
        )

    @staticmethod
    def _summarize_high_signal_observations(observations: list[AgentObservation]) -> str:
        """Create short high-signal summary."""

        text = " ".join(f"{obs.summary} {obs.metadata}" for obs in observations).lower()

        if any(term in text for term in ["critical", "rce", "remote code execution", "credential", "shell", "session"]):
            return "High-impact evidence was observed and should be prioritized for remediation."

        if any(term in text for term in ["web", "http", "https", "smb", "snmp", "open port"]):
            return "The assessment identified exposed services that should be reviewed and hardened."

        return "The available evidence should be reviewed for risk and follow-up validation."

    @staticmethod
    def _derive_recommendations(observations: list[AgentObservation]) -> list[str]:
        """Derive simple recommendations from observations."""

        text = " ".join(f"{obs.summary} {obs.metadata}" for obs in observations).lower()
        recommendations = ["Review all findings against the approved scope and validate remediation with retesting."]

        if any(term in text for term in ["cve", "outdated", "vulnerable"]):
            recommendations.append("Patch or upgrade vulnerable and outdated services.")

        if any(term in text for term in ["credential", "password", "hash", "mimikatz"]):
            recommendations.append("Rotate exposed credentials and review credential storage controls.")

        if any(term in text for term in ["smb", "snmp", "open port", "port 445", "port 161"]):
            recommendations.append("Restrict unnecessary network services and enforce least-privilege access controls.")

        if any(term in text for term in ["http", "https", "web", "nginx", "apache"]):
            recommendations.append("Harden exposed web applications and review web server security headers/configuration.")

        return recommendations
