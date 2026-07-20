"""MissionOrchestrator.run_mission must drive via MissionLoop, not a static plan."""

from unittest.mock import MagicMock

from saber.models.session import MissionSession
from saber.models.target import Target, TargetType


def test_run_mission_delegates_to_mission_loop(monkeypatch):
    from saber.orchestration import mission_orchestrator as mod

    captured = {}

    class _FakeLoop:
        def run(self, state, session):
            captured["state"] = state
            captured["session"] = session
            from saber.orchestration.mission_loop import MissionLoopResult

            return MissionLoopResult(state, session, mod.MissionRunStatus.COMPLETED, "done")

    orchestrator = mod.MissionOrchestrator(
        agents={"recon_agent": MagicMock(config=MagicMock(phase="reconnaissance"))},
        tool_registry=MagicMock(),
        sandbox=MagicMock(),
        mission_loop=_FakeLoop(),  # new injectable dependency
    )
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    result = orchestrator.run_mission(session=session, target=target, objective="assess")

    assert captured["state"].target.value == "10.0.0.5"
    assert result.status == mod.MissionRunStatus.COMPLETED
