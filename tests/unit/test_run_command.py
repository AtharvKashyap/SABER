"""CLI run-command orchestration tests.

The CLI ``run_cli_mission`` must drive the state-first ``MissionLoop`` in a
single pass: it calls ``orchestrator.run_mission`` exactly once and lets the
loop finalize the report. It must not re-run the whole mission for a separate
reporting phase (the retired plan-era two-phase split, which scanned the target
twice and could clobber a good report with an empty one).
"""

from __future__ import annotations

import saber.ui.cli.run_command as run_command
from saber.orchestration.execution_plan import build_default_execution_plan


class _FakeSession:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id


class _RunMissionResult:
    """Minimal stand-in for MissionRunResult (persist is stubbed in tests)."""

    def __init__(self, session_id: str) -> None:
        self.session = _FakeSession(session_id)
        self.status = "completed"
        self.records: list = []
        self.observations: list = []


class _FakeOrchestrator:
    def __init__(self) -> None:
        self.run_mission_calls = 0

    def create_plan(self, *, mission_name, target, objective, metadata=None):
        # A default plan includes a reporter_agent step, which is exactly what
        # the retired two-phase split used to fork a second run_mission call on.
        return build_default_execution_plan(
            mission_name=mission_name,
            target=target,
            objective=objective,
            metadata=metadata,
        )

    def run_mission(self, **kwargs):
        self.run_mission_calls += 1
        return _RunMissionResult(kwargs["session"].session_id)


class _FakeStore:
    def create_session(self, *args, **kwargs) -> None:
        pass

    def save_plan(self, *args, **kwargs) -> None:
        pass

    def update_session_status(self, *args, **kwargs) -> None:
        pass

    def list_steps(self, *args, **kwargs) -> list:
        return []

    def list_observations(self, *args, **kwargs) -> list:
        return []

    def list_evidence(self, *args, **kwargs) -> list:
        return []


class _FakeLlmClient:
    enabled = False


class _FakeRuntime:
    def __init__(self) -> None:
        self.orchestrator = _FakeOrchestrator()
        self.session_store = _FakeStore()
        self.finding_store = _FakeStore()
        self.evidence_index = _FakeStore()
        self.llm_client = _FakeLlmClient()
        self.agents: dict = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_run_cli_mission_calls_run_mission_exactly_once(monkeypatch, tmp_path):
    runtime = _FakeRuntime()

    monkeypatch.setattr(run_command, "build_saber_runtime", lambda config: runtime)
    monkeypatch.setattr(run_command, "persist_mission_result", lambda *a, **k: None)

    result = run_command.run_cli_mission(
        target_value="127.0.0.1",
        profile="recon",
        db_path=str(tmp_path / "saber.db"),
        evidence_dir=str(tmp_path / "evidence"),
        reports_dir=str(tmp_path / "reports"),
        agent_mode="deterministic",
        max_steps=5,
        dry_run=True,
    )

    # The whole point: one pass, one run_mission call (the loop finalizes the
    # report itself). Two calls would mean the mission ran twice.
    assert runtime.orchestrator.run_mission_calls == 1
    assert result["status"] == "completed"
    assert result["session_id"].startswith("session_")
    assert runtime.closed is True
