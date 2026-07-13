"""Planner → Orchestrator → Report E2E.

This verifies the real SABER control plane:
- PlannerAgent builds the executable plan
- MissionOrchestrator runs the plan
- StepRunner executes real safe agents/tools through Docker
- ResultProcessor processes evidence
- ReportFinalizer exports reports
- mission_result.json contains report artifacts
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from saber.agents.chain_agent import ChainAgent
from saber.agents.exploit_agent import ExploitAgent
from saber.agents.network_agent import NetworkAgent
from saber.agents.planner_agent import PlannerAgent
from saber.agents.recon_agent import ReconAgent
from saber.agents.web_agent import WebAgent
from saber.core.docker_runner import DockerSubprocessRunner, docker_available, docker_info, image_exists
from saber.core.evidence_store import EvidenceStore
from saber.core.result_processor import ResultProcessor
from saber.core.sandbox import Sandbox
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.chain_runner import ChainRunner
from saber.orchestration.mission_orchestrator import MissionOrchestrator, MissionRunStatus
from saber.orchestration.step_runner import StepRunner
from saber.reporting.finalizer import ReportFinalizer
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.tools.registry import ToolRegistry, default_tool_entries


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_planner_orchestrator_real_safe_pipeline_exports_reports(tmp_path) -> None:
    db_path = tmp_path / "saber.db"
    evidence_root = tmp_path / "evidence"
    reports_dir = tmp_path / "reports"

    connection = StorageConnection(db_path)
    connection.initialize()

    finding_store = FindingStore(connection)
    evidence_index = EvidenceIndex(connection)
    graph_store = GraphStore(connection)

    result_processor = ResultProcessor(
        evidence_index=evidence_index,
        finding_store=finding_store,
        graph_store=graph_store,
        evidence_root=evidence_root,
    )

    report_finalizer = ReportFinalizer(
        finding_store=finding_store,
        output_dir=reports_dir,
        connection=connection,
    )

    runner = DockerSubprocessRunner(
        image=os.getenv(
            "SABER_SANDBOX_IMAGE",
            "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release",
        ),
        repo_dir=Path.cwd(),
        default_timeout_seconds=240,
        network=os.getenv("SABER_DOCKER_NETWORK", "host"),
        user=os.getenv("SABER_DOCKER_USER", ""),
    )

    sandbox = Sandbox(EvidenceStore(evidence_root), runner)
    tool_registry = ToolRegistry(default_tool_entries())

    agents = {
        "planner_agent": PlannerAgent(),
        "recon_agent": ReconAgent(),
        "network_agent": NetworkAgent(),
        "web_agent": WebAgent(),
        "exploit_agent": ExploitAgent(),
        "chain_agent": ChainAgent(),
    }

    step_runner = StepRunner(
        agents=agents,
        tool_registry=tool_registry,
        sandbox=sandbox,
    )

    orchestrator = MissionOrchestrator(
        agents=agents,
        tool_registry=tool_registry,
        sandbox=sandbox,
        step_runner=step_runner,
        chain_runner=ChainRunner(),
        result_processor=result_processor,
        report_finalizer=report_finalizer,
        reports_dir=reports_dir,
        max_steps=8,
    )

    session = MissionSession(
        session_id="planner_orchestrator_report_e2e",
        mission_name="Planner Orchestrator Report E2E",
    )

    target = Target(type=TargetType.HOST, value="127.0.0.1")

    result_processor._ensure_session_exists(session.session_id)

    result = orchestrator.run_mission(
        session=session,
        target=target,
        objective="Run a safe local assessment of 127.0.0.1 and produce reports.",
        constraints={"agent_mode": "deterministic"},
        metadata={"target": target.tool_value(), "test": "planner_orchestrator_report_e2e"},
    )

    assert result.status in {
        MissionRunStatus.COMPLETED,
        MissionRunStatus.STOPPED,
        MissionRunStatus.PAUSED_FOR_APPROVAL,
    }

    assert result.records, "Expected orchestrator to run at least one step."

    mission_result_path = reports_dir / session.session_id / "mission_result.json"
    assert mission_result_path.exists()

    payload = json.loads(mission_result_path.read_text(encoding="utf-8"))

    assert payload["session_id"] == session.session_id
    assert payload["mission_name"] == session.mission_name
    assert payload["records"], "mission_result.json should include step records."

    # At least mission_result_json must exist. If the plan reaches completion,
    # report artifacts should also exist.
    artifact_kinds = {artifact["kind"] for artifact in payload["artifacts"]}
    assert "mission_result_json" in artifact_kinds

    if payload["status"] == "completed":
        assert "report_json" in artifact_kinds
        assert "report_xlsx" in artifact_kinds
        assert "report_markdown" in artifact_kinds
        assert (reports_dir / session.session_id / "findings.json").exists()
        assert (reports_dir / session.session_id / "findings.xlsx").exists()
        assert (reports_dir / session.session_id / "technical_report.md").exists()

    connection.close()
