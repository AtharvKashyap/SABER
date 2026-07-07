"""Tests for ReconAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.recon_agent import ReconAgent
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.capability import RequestedActionCategory
from saber.tools.registry import ToolRegistry, ToolRegistryEntry


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
        session_id="recon_session_1",
        mission_name="Recon Agent Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target(target_type: TargetType = TargetType.HOST, value: str = "example.com") -> Target:
    """Create target."""

    return Target(type=target_type, value=value)


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


def make_registry() -> ToolRegistry:
    """Create recon registry."""

    return ToolRegistry(
        [
            ToolRegistryEntry(
                name="nmap",
                import_path="saber.tools.recon.nmap",
                class_name="NmapWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
            ToolRegistryEntry(
                name="masscan",
                import_path="saber.tools.recon.masscan",
                class_name="MasscanWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
            ToolRegistryEntry(
                name="subfinder",
                import_path="saber.tools.recon.subfinder",
                class_name="SubfinderWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
            ToolRegistryEntry(
                name="dnsrecon",
                import_path="saber.tools.recon.dnsrecon",
                class_name="DNSReconWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
            ToolRegistryEntry(
                name="theharvester",
                import_path="saber.tools.recon.theharvester",
                class_name="TheHarvesterWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
            ToolRegistryEntry(
                name="custom_cli",
                import_path="saber.tools.custom_cli",
                class_name="CustomCliWrapper",
                category=RequestedActionCategory.UNKNOWN,
                phase=AssessmentPhase.RECON,
            ),
        ]
    )


def make_context(
    observations: list[AgentObservation] | None = None,
    objective: str = "Perform recon.",
    target: Target | None = None,
    sandbox: FakeSandbox | None = None,
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=target or make_target(),
        sandbox=sandbox or FakeSandbox(),
        tool_registry=make_registry(),
        objective=objective,
        phase=AssessmentPhase.RECON,
        observations=observations or [],
    )


class TestReconAgent:
    """Validate ReconAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = ReconAgent()

        assert agent.config.name == "recon_agent"
        assert agent.config.phase == AssessmentPhase.RECON
        assert agent.config.prompt_path == "prompts/recon_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "recon"

    def test_default_selects_nmap_service_scan(self) -> None:
        """Default recon should choose nmap service scan."""

        agent = ReconAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "nmap"
        assert decision.tool_call.action == "service_scan"
        assert decision.metadata["workflow_step"] == "service_discovery"

    def test_domain_target_selects_subfinder(self) -> None:
        """Domain target should select subfinder."""

        agent = ReconAgent()
        target = make_target(TargetType.DOMAIN, "example.com")

        decision = agent.decide(make_context(target=target))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "subfinder"
        assert decision.tool_call.action == "passive"
        assert decision.tool_call.args["domain"] == "example.com"
        assert decision.metadata["workflow_step"] == "subdomain_discovery"

    def test_dns_objective_selects_dnsrecon(self) -> None:
        """DNS objective should select dnsrecon."""

        agent = ReconAgent()

        decision = agent.decide(make_context(objective="Enumerate DNS records."))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "dnsrecon"
        assert decision.tool_call.action == "standard"
        assert decision.metadata["workflow_step"] == "dns_enumeration"

    def test_osint_objective_selects_theharvester(self) -> None:
        """OSINT objective should select theHarvester."""

        agent = ReconAgent()

        decision = agent.decide(make_context(objective="Perform OSINT email harvest."))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "theharvester"
        assert decision.tool_call.action == "search"
        assert decision.metadata["workflow_step"] == "osint_harvesting"

    def test_fast_scan_objective_selects_masscan(self) -> None:
        """Fast scan objective should select masscan."""

        agent = ReconAgent()

        decision = agent.decide(make_context(objective="Run fast scan across many hosts."))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "masscan"
        assert decision.tool_call.action == "top_ports"
        assert decision.metadata["workflow_step"] == "fast_port_discovery"

    def test_web_observation_hands_to_web_agent(self) -> None:
        """Web observations should hand off to web agent."""

        agent = ReconAgent()
        observations = [AgentObservation(summary="HTTP service on port 80 running nginx.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "web_agent"
        assert decision.metadata["reason"] == "web_surface_discovered"

    def test_recon_complete_stops(self) -> None:
        """Complete objective should stop."""

        agent = ReconAgent()

        decision = agent.decide(make_context(objective="Recon complete."))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "recon_complete"

    def test_run_handoff_result(self) -> None:
        """Run should return handoff for web surface."""

        agent = ReconAgent()
        observations = [AgentObservation(summary="HTTPS service on port 443.")]

        result = agent.run(make_context(observations=observations))

        assert result.status == AgentRunStatus.HANDOFF
        assert result.decision.handoff_agent == "web_agent"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI helper should require approval."""

        agent = ReconAgent()

        decision = agent.build_custom_cli_decision(
            command="curl -I https://example.com",
            reason="Need a one-off header check.",
            expected_output="HTTP headers",
            risk_level="low",
            metadata={"ticket": "RECON-CLI"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.args["risk_level"] == "low"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "RECON-CLI"

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = ReconAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=make_registry(),
            objective="Wrong phase.",
            phase=AssessmentPhase.EXPLOITATION,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)
