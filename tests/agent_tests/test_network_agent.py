"""Tests for NetworkAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.network_agent import NetworkAgent
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
        session_id="network_session_1",
        mission_name="Network Agent Test Mission",
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


def make_registry() -> ToolRegistry:
    """Create network registry."""

    return ToolRegistry(
        [
            ToolRegistryEntry(
                name="enum4linux",
                import_path="saber.tools.network.enum4linux",
                class_name="Enum4LinuxWrapper",
                category=RequestedActionCategory.NETWORK,
                phase=AssessmentPhase.NETWORK,
            ),
            ToolRegistryEntry(
                name="snmpwalk",
                import_path="saber.tools.network.snmpwalk",
                class_name="SnmpwalkWrapper",
                category=RequestedActionCategory.NETWORK,
                phase=AssessmentPhase.NETWORK,
            ),
            ToolRegistryEntry(
                name="openvas",
                import_path="saber.tools.network.openvas_api",
                class_name="OpenVASApiWrapper",
                category=RequestedActionCategory.NETWORK,
                phase=AssessmentPhase.NETWORK,
                aliases=("openvas_api",),
            ),
            ToolRegistryEntry(
                name="responder",
                import_path="saber.tools.network.responder",
                class_name="ResponderWrapper",
                category=RequestedActionCategory.NETWORK,
                phase=AssessmentPhase.NETWORK,
            ),
            ToolRegistryEntry(
                name="bettercap",
                import_path="saber.tools.network.bettercap",
                class_name="BettercapWrapper",
                category=RequestedActionCategory.NETWORK,
                phase=AssessmentPhase.NETWORK,
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
    objective: str = "Enumerate network services.",
    sandbox: FakeSandbox | None = None,
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=sandbox or FakeSandbox(),
        tool_registry=make_registry(),
        objective=objective,
        phase=AssessmentPhase.NETWORK,
        observations=observations or [],
    )


class TestNetworkAgent:
    """Validate NetworkAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = NetworkAgent()

        assert agent.config.name == "network_agent"
        assert agent.config.phase == AssessmentPhase.NETWORK
        assert agent.config.prompt_path == "prompts/network_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "network"

    def test_smb_observation_selects_enum4linux(self) -> None:
        """SMB evidence should select enum4linux."""

        agent = NetworkAgent()
        observations = [AgentObservation(summary="Port 445 SMB is open on the target.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "enum4linux"
        assert decision.tool_call.action == "shares"
        assert decision.metadata["workflow_step"] == "smb_enum"

    def test_snmp_observation_selects_snmpwalk(self) -> None:
        """SNMP evidence should select snmpwalk."""

        agent = NetworkAgent()
        observations = [AgentObservation(summary="UDP/161 SNMP is open.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "snmpwalk"
        assert decision.tool_call.action == "walk"
        assert decision.tool_call.args["community"] == "public"
        assert decision.metadata["workflow_step"] == "snmp_enum"

    def test_vulnerability_scan_objective_selects_openvas(self) -> None:
        """OpenVAS objective should select target creation."""

        agent = NetworkAgent()

        decision = agent.decide(make_context(objective="Create OpenVAS vulnerability scan target."))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "openvas"
        assert decision.tool_call.action == "create_target"
        assert decision.tool_call.args["name"] == "saber-target"
        assert decision.metadata["workflow_step"] == "openvas_target"

    def test_no_observations_hands_to_recon(self) -> None:
        """No observations should hand off to recon."""

        agent = NetworkAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "recon_agent"
        assert decision.metadata["reason"] == "missing_network_observations"

    def test_irrelevant_observations_stop(self) -> None:
        """Irrelevant observations should stop."""

        agent = NetworkAgent()
        observations = [AgentObservation(summary="No network services were found.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "no_network_action"

    def test_run_handoff_result(self) -> None:
        """Run should return handoff when no observations exist."""

        agent = NetworkAgent()

        result = agent.run(make_context())

        assert result.status == AgentRunStatus.HANDOFF
        assert result.decision.handoff_agent == "recon_agent"

    def test_run_smb_executes_enum4linux(self) -> None:
        """SMB decision should execute through registry/sandbox."""

        sandbox = FakeSandbox()
        agent = NetworkAgent()
        observations = [AgentObservation(summary="SMB port 445 open.")]

        result = agent.run(make_context(observations=observations, sandbox=sandbox))

        assert result.status == AgentRunStatus.COMPLETED
        assert len(sandbox.requests) == 1
        assert sandbox.requests[0].tool_request.tool_name == "enum4linux"
        assert sandbox.requests[0].tool_request.action == "shares"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.NETWORK
        assert sandbox.requests[0].tool_request.metadata["agent_name"] == "network_agent"

    def test_responder_approval_decision(self) -> None:
        """Responder helper should require approval."""

        agent = NetworkAgent()

        decision = agent.build_responder_approval_decision(
            interface="eth0",
            reason="Capture workflow requires explicit operator approval.",
            metadata={"ticket": "NET-RESP"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "responder"
        assert decision.tool_call.action == "listen"
        assert decision.tool_call.args["interface"] == "eth0"
        assert decision.metadata["approval_type"] == "responder"
        assert decision.metadata["ticket"] == "NET-RESP"

    def test_bettercap_approval_decision(self) -> None:
        """Bettercap helper should require approval."""

        agent = NetworkAgent()

        decision = agent.build_bettercap_approval_decision(
            interface="eth1",
            reason="Network action requires explicit approval.",
            metadata={"ticket": "NET-BETTER"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "bettercap"
        assert decision.tool_call.action == "net_recon"
        assert decision.tool_call.args["interface"] == "eth1"
        assert decision.metadata["approval_type"] == "bettercap"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI helper should require approval."""

        agent = NetworkAgent()

        decision = agent.build_custom_cli_decision(
            command="ip route",
            reason="Need one-off routing context.",
            expected_output="Routing table",
            risk_level="low",
            metadata={"ticket": "NET-CLI"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.args["risk_level"] == "low"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "NET-CLI"

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = NetworkAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=make_registry(),
            objective="Wrong phase.",
            phase=AssessmentPhase.RECON,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)
