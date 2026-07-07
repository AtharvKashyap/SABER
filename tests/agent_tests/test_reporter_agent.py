"""Tests for ReporterAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.reporter_agent import ReportDraft, ReporterAgent, ReportSection
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.registry import ToolRegistry


@dataclass
class FakeSandbox:
    """Fake sandbox."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_session() -> MissionSession:
    """Create session."""

    return MissionSession(
        session_id="reporter_session_1",
        mission_name="Reporter Agent Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create sandbox result."""

    return SandboxExecutionResult(
        outcome=SandboxOutcome.EXECUTED,
        allowed=True,
        session=session or make_session(),
        evidence=None,
        return_code=0,
        stdout="ok",
        stderr="",
        reason="Command executed and evidence was saved.",
        metadata={"backend": "fake", "finished_at": datetime.now(UTC).isoformat()},
    )


def make_context(
    observations: list[AgentObservation] | None = None,
    objective: str = "Generate final report.",
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=FakeSandbox(),
        tool_registry=ToolRegistry([]),
        objective=objective,
        phase=AssessmentPhase.REPORTING,
        observations=observations or [],
    )


class TestReporterModels:
    """Validate reporter data models."""

    def test_report_section_validates_title(self) -> None:
        """Empty title should raise."""

        with pytest.raises(ValueError, match="ReportSection.title cannot be empty"):
            ReportSection(title="", content="content")

    def test_report_section_validates_content(self) -> None:
        """Empty content should raise."""

        with pytest.raises(ValueError, match="ReportSection.content cannot be empty"):
            ReportSection(title="Title", content="")

    def test_report_section_markdown_and_dict(self) -> None:
        """Section should render Markdown and dict."""

        section = ReportSection(title="Summary", content="Assessment complete.", metadata={"type": "summary"})

        assert section.to_markdown() == "## Summary\n\nAssessment complete.\n"
        assert section.to_dict() == {
            "title": "Summary",
            "content": "Assessment complete.",
            "metadata": {"type": "summary"},
        }

    def test_report_draft_requires_sections(self) -> None:
        """Draft should require sections."""

        with pytest.raises(ValueError, match="ReportDraft.sections cannot be empty"):
            ReportDraft(title="Report", sections=[])

    def test_report_draft_markdown_and_dict(self) -> None:
        """Draft should render Markdown and dict."""

        draft = ReportDraft(
            title="SABER Report",
            sections=[ReportSection(title="Summary", content="Done.")],
            metadata={"target": "example.com"},
        )

        assert draft.to_markdown() == "# SABER Report\n\n## Summary\n\nDone.\n"
        data = draft.to_dict()
        assert data["title"] == "SABER Report"
        assert data["sections"][0]["title"] == "Summary"
        assert data["metadata"]["target"] == "example.com"


class TestReporterAgent:
    """Validate ReporterAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = ReporterAgent()

        assert agent.config.name == "reporter_agent"
        assert agent.config.phase == AssessmentPhase.REPORTING
        assert agent.config.prompt_path == "prompts/reporter_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "reporter"

    def test_no_observations_stops_missing_evidence(self) -> None:
        """No observations should stop."""

        agent = ReporterAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "missing_report_evidence"

    def test_build_report_draft(self) -> None:
        """Report draft should include core sections."""

        agent = ReporterAgent()
        observations = [
            AgentObservation(summary="Port 443 open with nginx.", tool_name="nmap", action="service_scan"),
            AgentObservation(summary="CVE-2024-0001 appears applicable.", tool_name="searchsploit", action="cve_search"),
        ]

        draft = agent.build_report_draft(make_context(observations=observations))

        titles = [section.title for section in draft.sections]

        assert draft.title == "SABER Assessment Report - example.com"
        assert titles == [
            "Executive Summary",
            "Scope and Objective",
            "Technical Findings and Observations",
            "Assessment Timeline",
            "Recommendations",
        ]
        assert draft.metadata["observation_count"] == 2

    def test_decide_generates_report_metadata(self) -> None:
        """Decision should include report dict and markdown."""

        agent = ReporterAgent()
        observations = [AgentObservation(summary="HTTP service found.", tool_name="nmap", action="service_scan")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "report_generated"
        assert "report" in decision.metadata
        assert "markdown" in decision.metadata
        assert "# SABER Assessment Report - example.com" in decision.metadata["markdown"]

    def test_run_report_result_stopped(self) -> None:
        """Run should return stopped after report generation."""

        agent = ReporterAgent()
        observations = [AgentObservation(summary="SMB port 445 open.", tool_name="nmap", action="service_scan")]

        result = agent.run(make_context(observations=observations))

        assert result.status == AgentRunStatus.STOPPED
        assert result.decision.metadata["reason"] == "report_generated"

    def test_recommendations_include_network_and_web(self) -> None:
        """Recommendations should derive from observations."""

        agent = ReporterAgent()
        observations = [
            AgentObservation(summary="HTTP service exposed on nginx."),
            AgentObservation(summary="SMB port 445 is open."),
        ]

        draft = agent.build_report_draft(make_context(observations=observations))
        recommendations = next(section for section in draft.sections if section.title == "Recommendations")

        assert "Restrict unnecessary network services" in recommendations.content
        assert "Harden exposed web applications" in recommendations.content

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = ReporterAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=ToolRegistry([]),
            objective="Wrong phase.",
            phase=AssessmentPhase.RECON,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)
