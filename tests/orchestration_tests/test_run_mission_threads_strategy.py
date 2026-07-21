"""run_mission must thread the per-mission strategy into MissionLoop.run.

Production builds MissionLoop as a target-agnostic singleton (runtime.py) before
any target is known, so the loop's constructor ``strategy`` is always None in
prod. The per-mission strategy is selected inside ``run_mission`` and must be
passed through ``run(...)`` for ``objective_met`` to fire. These tests inject a
fake loop that captures the ``strategy`` kwarg and assert the right strategy
instance arrives for the target/metadata.
"""

from unittest.mock import MagicMock

from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration import mission_orchestrator as mod
from saber.orchestration.strategies.ctf import CtfStrategy
from saber.orchestration.strategies.web import WebStrategy


def _orchestrator_with_capture(captured):
    """Build an orchestrator whose loop records the strategy kwarg it receives."""

    class _FakeLoop:
        def run(self, state, session, strategy=None):
            captured["strategy"] = strategy
            from saber.orchestration.mission_loop import MissionLoopResult

            return MissionLoopResult(state, session, mod.MissionRunStatus.COMPLETED, "done")

    return mod.MissionOrchestrator(
        agents={"recon_agent": MagicMock(config=MagicMock(phase="reconnaissance"))},
        tool_registry=MagicMock(),
        sandbox=MagicMock(),
        mission_loop=_FakeLoop(),
    )


def test_url_target_threads_web_strategy_into_loop_run():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.URL, value="http://x/")

    orchestrator.run_mission(session=session, target=target, objective="")

    # The strategy selected for a URL target must reach MissionLoop.run so that
    # objective_met is actually consulted in production.
    assert isinstance(captured["strategy"], WebStrategy)


def test_ctf_metadata_threads_ctf_strategy_into_loop_run():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    orchestrator.run_mission(session=session, target=target, objective="", metadata={"ctf": True})

    assert isinstance(captured["strategy"], CtfStrategy)
