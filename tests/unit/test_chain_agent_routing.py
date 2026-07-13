"""ChainAgent routing tests."""

from __future__ import annotations

from types import SimpleNamespace

from saber.agents.base_agent import AgentActionType, AgentObservation
from saber.agents.chain_agent import ChainAgent
from saber.orchestration.chain_runner import ChainRunner
from saber.orchestration.execution_plan import ExecutionPlan, ExecutionStep, ExecutionStepStatus
from saber.models.scope import AssessmentPhase
from saber.models.target import Target, TargetType


def _context(observations):
    return SimpleNamespace(
        objective="Choose the next mission phase from parsed findings.",
        observations=observations,
        constraints={"agent_mode": "deterministic"},
        metadata={},
    )


def _obs(summary: str, metadata: dict | None = None) -> AgentObservation:
    return AgentObservation(
        summary=summary,
        tool_name="nmap",
        action="service_scan",
        success=True,
        metadata=metadata or {},
    )


def test_chain_agent_routes_http_surface_to_web_agent() -> None:
    decision = ChainAgent().decide(
        _context([
            _obs(
                "Open service discovered: 127.0.0.1:80/tcp",
                {
                    "finding_type": "open_service",
                    "service": "http",
                    "port": 80,
                },
            )
        ])
    )

    assert decision.action_type == AgentActionType.HANDOFF
    assert decision.handoff_agent == "web_agent"
    assert decision.metadata["reason"] == "web_surface_observed"


def test_chain_agent_routes_network_surface_to_network_agent() -> None:
    decision = ChainAgent().decide(
        _context([
            _obs(
                "Open service discovered: 127.0.0.1:111/tcp is open running rpcbind.",
                {
                    "finding_type": "open_service",
                    "service": "rpcbind",
                    "port": 111,
                },
            )
        ])
    )

    assert decision.action_type == AgentActionType.HANDOFF
    assert decision.handoff_agent == "network_agent"
    assert decision.metadata["reason"] == "network_surface_observed"


def test_chain_agent_routes_possible_vuln_to_exploit_agent() -> None:
    decision = ChainAgent().decide(
        _context([
            _obs(
                "Possible CVE found on exposed service.",
                {
                    "cve_ids": ["CVE-2099-0001"],
                    "severity": "high",
                },
            )
        ])
    )

    assert decision.action_type == AgentActionType.HANDOFF
    assert decision.handoff_agent == "exploit_agent"
    assert decision.metadata["reason"] == "possible_vulnerability"


def test_chain_agent_routes_no_actionable_surface_to_reporter_agent() -> None:
    decision = ChainAgent().decide(
        _context([
            _obs(
                "Host 127.0.0.1 is up.",
                {
                    "kind": "host",
                    "state": "up",
                },
            )
        ])
    )

    assert decision.action_type == AgentActionType.HANDOFF
    assert decision.handoff_agent == "reporter_agent"
    assert decision.metadata["reason"] == "ready_for_reporting"


def test_chain_runner_adds_handoff_step_from_chain_decision() -> None:
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    start_step = ExecutionStep(
        step_id="chain_step",
        agent_name="chain_agent",
        objective="Choose next phase.",
        phase=AssessmentPhase.EXPLOITATION,
        target=target,
    )

    plan = ExecutionPlan(
        plan_id="chain_plan",
        mission_name="Chain Routing Test",
        steps=[start_step],
    )

    decision = ChainAgent().decide(
        _context([
            _obs(
                "Open service discovered: 127.0.0.1:111/tcp is open running rpcbind.",
                {
                    "finding_type": "open_service",
                    "service": "rpcbind",
                    "port": 111,
                },
            )
        ])
    )

    record = SimpleNamespace(
        step_id="chain_step",
        agent_name="chain_agent",
        status=ExecutionStepStatus.HANDOFF,
        handoff_agent=decision.handoff_agent,
        requires_approval=False,
        metadata={},
        agent_result=SimpleNamespace(
            status=SimpleNamespace(value="handoff"),
            decision=decision,
        ),
    )

    updated = ChainRunner().process_step_record(plan, record)

    assert updated.get_step("chain_step").status == ExecutionStepStatus.HANDOFF
    assert any(step.agent_name == "network_agent" for step in updated.steps)
