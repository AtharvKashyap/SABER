"""Tests for WebAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.web_agent import WebAgent
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
        session_id="web_session_1",
        mission_name="Web Agent Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.URL, value="https://example.com")


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
    objective: str = "Test web app.",
    metadata: dict | None = None,
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=FakeSandbox(),
        tool_registry=ToolRegistry([]),
        objective=objective,
        phase=AssessmentPhase.RECON,
        observations=observations or [],
        metadata=metadata or {},
    )


class TestWebAgent:
    """Validate WebAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = WebAgent()

        assert agent.config.name == "web_agent"
        assert agent.config.phase == AssessmentPhase.RECON
        assert agent.config.prompt_path == "prompts/web_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "web"

    def test_no_fingerprint_selects_whatweb(self) -> None:
        """Initial web step should fingerprint."""

        agent = WebAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "whatweb"
        assert decision.tool_call.action == "fingerprint"
        assert decision.tool_call.args["aggression"] == 2
        assert decision.metadata["workflow_step"] == "web_fingerprinting"

    def test_content_discovery_selects_feroxbuster(self) -> None:
        """Content discovery should select feroxbuster after fingerprinting."""

        agent = WebAgent()
        observations = [AgentObservation(summary="whatweb fingerprint found nginx.", tool_name="whatweb")]

        decision = agent.decide(
            make_context(
                observations=observations,
                objective="Run directory content discovery.",
                metadata={"wordlist": "wordlists/big.txt", "threads": 25},
            )
        )

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "feroxbuster"
        assert decision.tool_call.action == "directory_bruteforce"
        assert decision.tool_call.args["wordlist"] == "wordlists/big.txt"
        assert decision.tool_call.args["threads"] == 25
        assert decision.metadata["workflow_step"] == "content_discovery"

    def test_nikto_objective_selects_nikto(self) -> None:
        """Nikto objective should select nikto after fingerprinting."""

        agent = WebAgent()
        observations = [AgentObservation(summary="whatweb fingerprint found Apache.", tool_name="whatweb")]

        decision = agent.decide(
            make_context(
                observations=observations,
                objective="Run web server scan for misconfiguration.",
                metadata={"json_output": True},
            )
        )

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "nikto"
        assert decision.tool_call.action == "scan"
        assert decision.tool_call.args["output_format"] == "json"
        assert decision.metadata["workflow_step"] == "web_server_scan"

    def test_nuclei_objective_selects_nuclei(self) -> None:
        """Template scan should select nuclei after fingerprinting."""

        agent = WebAgent()
        observations = [AgentObservation(summary="whatweb fingerprint found nginx.", tool_name="whatweb")]

        decision = agent.decide(
            make_context(
                observations=observations,
                objective="Run nuclei template scan for known vulnerabilities.",
                metadata={"severity": "high,critical", "templates": "templates/cves"},
            )
        )

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "nuclei"
        assert decision.tool_call.action == "scan"
        assert decision.tool_call.args["severity"] == "high,critical"
        assert decision.tool_call.args["templates"] == "templates/cves"
        assert decision.metadata["workflow_step"] == "template_scan"

    def test_sqli_observation_selects_sqlmap(self) -> None:
        """Possible SQLi should select sqlmap validation."""

        agent = WebAgent()
        observations = [
            AgentObservation(summary="whatweb fingerprint found nginx.", tool_name="whatweb"),
            AgentObservation(summary="Parameter appears injectable; possible SQL injection."),
        ]

        decision = agent.decide(make_context(observations=observations))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "sqlmap"
        assert decision.tool_call.action == "test_url"
        assert decision.tool_call.args == {"risk": 1, "level": 1, "batch": True}
        assert decision.metadata["workflow_step"] == "sqli_validation"

    def test_zap_baseline_selects_zap(self) -> None:
        """ZAP baseline should select zap_api."""

        agent = WebAgent()
        observations = [AgentObservation(summary="whatweb fingerprint found IIS.", tool_name="whatweb")]

        decision = agent.decide(
            make_context(
                observations=observations,
                objective="Run ZAP baseline web scan.",
                metadata={"report_file": "zap.html"},
            )
        )

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "zap_api"
        assert decision.tool_call.action == "baseline_scan"
        assert decision.tool_call.args["report_file"] == "zap.html"
        assert decision.metadata["workflow_step"] == "zap_baseline"

    def test_complete_context_stops(self) -> None:
        """Complete web objective should stop."""

        agent = WebAgent()

        decision = agent.decide(make_context(objective="Web testing complete."))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "web_complete"

    def test_no_additional_action_stops(self) -> None:
        """If fingerprinting exists and no objective matches, stop."""

        agent = WebAgent()
        observations = [AgentObservation(summary="whatweb fingerprint found nginx.", tool_name="whatweb")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "no_web_action"

    def test_zap_active_scan_approval_decision(self) -> None:
        """ZAP active scan helper should require approval."""

        agent = WebAgent()

        decision = agent.build_zap_active_scan_approval_decision(
            reason="Active scan can affect the app.",
            zap_url="http://127.0.0.1:8080",
            metadata={"ticket": "WEB-ZAP"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "zap_api"
        assert decision.tool_call.action == "active_scan"
        assert decision.metadata["approval_type"] == "zap_active_scan"
        assert decision.metadata["ticket"] == "WEB-ZAP"

    def test_sqlmap_schema_approval_decision(self) -> None:
        """sqlmap schema helper should require approval."""

        agent = WebAgent()

        decision = agent.build_sqlmap_schema_approval_decision(
            reason="Schema enumeration requires approval.",
            metadata={"ticket": "WEB-SQLMAP"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "sqlmap"
        assert decision.tool_call.action == "dump_schema"
        assert decision.metadata["approval_type"] == "sqlmap_dump_schema"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI helper should require approval."""

        agent = WebAgent()

        decision = agent.build_custom_cli_decision(
            command="curl -I https://example.com",
            reason="Need one-off header check.",
            expected_output="HTTP headers",
            risk_level="low",
            metadata={"ticket": "WEB-CLI"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.args["risk_level"] == "low"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "WEB-CLI"

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = WebAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=ToolRegistry([]),
            objective="Wrong phase.",
            phase=AssessmentPhase.EXPLOITATION,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)

    def test_run_stop_result(self) -> None:
        """Run should return stopped when complete."""

        agent = WebAgent()

        result = agent.run(make_context(objective="Web complete."))

        assert result.status == AgentRunStatus.STOPPED
        assert result.decision.metadata["reason"] == "web_complete"
