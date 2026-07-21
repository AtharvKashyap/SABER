"""Deterministic full-pipeline mission E2E (Docker-gated, no LLM key needed).

This exercises the real SABER control plane end to end through the CURRENT
state-first architecture:

- ``build_saber_runtime`` wires storage, tools, parsers, sandbox, the mission
  loop, and the report finalizer.
- ``MissionOrchestrator.run_mission`` drives the injected ``MissionLoop`` with
  the ``DeterministicDecider`` (so this needs Docker but NOT a live model).
- Real safe tools run in the Docker sandbox; ``ResultProcessor`` parses their
  evidence into the stores.
- ``ReportFinalizer`` exports report artifacts from the final ``MissionState``.

Task 13 retired the plan-first driver (``run_until_pause_or_complete`` + a
static chain runner), and Task 17 rewrote this test onto the loop/runtime API.
It asserts loop INVARIANTS (terminates, no scope violation, work attempted,
reports produced) rather than an exact tool order.

The live-LLM counterpart (state-growth against real targets) lives in
``test_mission_loop_live_llm_e2e.py``; this test is its deterministic,
model-free sibling and is gated on Docker only.
"""

from __future__ import annotations

import os

import pytest
from saber.core.docker_runner import docker_available, docker_info, image_exists
from saber.core.runtime import SaberConfig, build_saber_runtime
from saber.models.scope import MissionScope
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.storage.mission_state_store import MissionStateStore

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
def test_deterministic_mission_pipeline_exports_reports(tmp_path) -> None:
    session_id = "planner_orchestrator_report_e2e"
    config = SaberConfig(
        db_path=tmp_path / "saber.db",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        profile="recon",
        require_approval=False,
        max_steps=8,
        agent_mode="deterministic",
        metadata={"source": "planner_orchestrator_report_e2e"},
    )
    runtime = build_saber_runtime(config)

    try:
        target = Target(type=TargetType.IP, value="127.0.0.1")
        scope = MissionScope(mission_name="Deterministic pipeline E2E", targets=[target])
        session = MissionSession(
            session_id=session_id,
            mission_name="Deterministic Pipeline E2E",
            scope=scope,
        )

        runtime.session_store.create_session(
            {
                "session_id": session_id,
                "mission_name": session.mission_name,
                "status": "running",
                "metadata": {"target": target.value, "profile": "recon"},
            }
        )

        result = runtime.orchestrator.run_mission(
            session=session,
            target=target,
            objective="Run a safe local assessment of 127.0.0.1 and produce reports.",
            constraints={"autonomy_level": "autonomous", "agent_mode": "deterministic"},
            metadata={"source": "planner_orchestrator_report_e2e"},
        )

        # 1. The loop terminates with a terminal status.
        assert result.status in {
            MissionRunStatus.COMPLETED,
            MissionRunStatus.STOPPED,
            MissionRunStatus.PAUSED_FOR_APPROVAL,
        }

        # 2. State is persisted, work was attempted, and no scope violation occurred.
        # (The DeterministicDecider always attempts nmap service_scan first, so a
        # deterministic run reliably attempts at least one action; service
        # discovery depends on the live host and is asserted in the live-LLM test.)
        state = MissionStateStore(runtime.storage_connection).load(session_id)
        assert state is not None, "mission loop must persist a MissionState snapshot"
        assert len(state.attempted_actions) >= 1, "expected the loop to attempt >=1 action"
        assert not [
            attempt for attempt in state.attempted_actions
            if "out of scope" in (attempt.reason or "").lower()
        ], "no scope violation should be recorded for an in-scope target"

        # 3. On a finalized run, report artifacts are exported to disk.
        if result.status in {MissionRunStatus.COMPLETED, MissionRunStatus.STOPPED}:
            assert result.artifacts, "expected report artifacts on a finalized run"
            report_types = {artifact.kind for artifact in result.artifacts}
            assert "json" in report_types, f"expected a JSON report; got {report_types}"

            session_reports = tmp_path / "reports" / session_id
            assert (session_reports / "findings.json").exists()
    finally:
        runtime.close()
