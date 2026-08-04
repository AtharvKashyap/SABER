"""PlannerAgent execution-plan tests."""

from __future__ import annotations

from unittest.mock import MagicMock

from saber.agents.planner_agent import PlannerAgent
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.target import Target, TargetType
from saber.orchestration.mission_orchestrator import MissionOrchestrator
from saber.tools.registry import ToolRegistry


class NoExecuteRunner:
    def run(self, command, **kwargs):
        raise AssertionError("This test should not execute tools.")


def test_planner_agent_builds_execution_plan_from_mission_plan(tmp_path) -> None:
    planner = PlannerAgent()
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    plan = planner.build_execution_plan(
        mission_name="Planner Brain Test",
        target=target,
        objective="Assess 127.0.0.1.",
        available_agents={
            "planner_agent",
            "recon_agent",
            "network_agent",
            "web_agent",
            "exploit_agent",
        },
        metadata={"test": "planner_execution_plan"},
    )

    assert plan.mission_name == "Planner Brain Test"
    assert plan.metadata["planned_by"] == "planner_agent"
    assert plan.metadata["test"] == "planner_execution_plan"

    agent_names = [step.agent_name for step in plan.steps]
    assert agent_names == [
        "recon_agent",
        "network_agent",
        "web_agent",
        "exploit_agent",
    ]

    assert plan.steps[0].phase == AssessmentPhase.RECON
    assert plan.steps[0].target == target
    assert plan.steps[1].depends_on == [plan.steps[0].step_id]
    assert plan.steps[2].depends_on == [plan.steps[0].step_id]
    assert plan.steps[3].depends_on == [
        plan.steps[0].step_id,
        plan.steps[1].step_id,
        plan.steps[2].step_id,
    ]


def test_orchestrator_create_plan_uses_planner_agent_when_present(tmp_path) -> None:
    planner = PlannerAgent()
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    orchestrator = MissionOrchestrator(
        agents={
            "planner_agent": planner,
            "recon_agent": planner,  # placeholder; create_plan only needs names here
        },
        tool_registry=ToolRegistry([]),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), NoExecuteRunner()),
        reports_dir=tmp_path / "reports",
        mission_loop=MagicMock(),
    )

    plan = orchestrator.create_plan(
        mission_name="Orchestrator Planner Test",
        target=target,
        objective="Assess localhost.",
        metadata={"source": "unit_test"},
    )

    assert plan.metadata["planned_by"] == "planner_agent"
    assert plan.metadata["source"] == "unit_test"
    assert [step.agent_name for step in plan.steps] == ["recon_agent"]
    assert plan.steps[0].metadata["planned_by"] == "planner_agent"


def test_orchestrator_create_plan_falls_back_without_planner_agent(tmp_path) -> None:
    planner = PlannerAgent()
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    orchestrator = MissionOrchestrator(
        agents={"recon_agent": planner},
        tool_registry=ToolRegistry([]),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), NoExecuteRunner()),
        reports_dir=tmp_path / "reports",
        mission_loop=MagicMock(),
    )

    plan = orchestrator.create_plan(
        mission_name="Fallback Planner Test",
        target=target,
        objective="Assess localhost.",
    )

    assert plan.mission_name == "Fallback Planner Test"
    assert plan.steps
    assert plan.metadata.get("planned_by") != "planner_agent"
