"""run_mission must seed the selected strategy's objective and metadata onto MissionState."""

from unittest.mock import MagicMock

from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration import mission_orchestrator as mod


def _orchestrator_with_capture(captured):
    """Build an orchestrator whose loop just records the state it receives."""

    class _FakeLoop:
        def run(self, state, session, strategy=None):
            captured["state"] = state
            from saber.orchestration.mission_loop import MissionLoopResult

            return MissionLoopResult(state, session, mod.MissionRunStatus.COMPLETED, "done")

    return mod.MissionOrchestrator(
        agents={"recon_agent": MagicMock(config=MagicMock(phase="reconnaissance"))},
        tool_registry=MagicMock(),
        sandbox=MagicMock(),
        mission_loop=_FakeLoop(),
    )


def test_blank_objective_seeded_from_network_strategy():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    result = orchestrator.run_mission(session=session, target=target, objective="")

    # Network strategy seeds the objective and stamps its kind into metadata.
    assert "identify services and known vulnerabilities" in captured["state"].objective
    assert captured["state"].metadata["strategy"] == "network"
    # And the seeded objective surfaces in the run-result summary.
    assert (
        "identify services and known vulnerabilities"
        in result.metadata["mission_state"]["objective"]
    )


def test_whitespace_objective_is_treated_as_blank():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    orchestrator.run_mission(session=session, target=target, objective="   ")

    assert captured["state"].objective.strip() != ""
    assert "identify services and known vulnerabilities" in captured["state"].objective


def test_explicit_objective_is_preserved():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    orchestrator.run_mission(session=session, target=target, objective="custom objective")

    assert captured["state"].objective == "custom objective"
    # Strategy metadata is still seeded even when the objective is caller-supplied.
    assert captured["state"].metadata["strategy"] == "network"


def test_url_target_seeds_web_strategy():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.URL, value="http://x/")

    orchestrator.run_mission(session=session, target=target, objective="")

    assert captured["state"].metadata["strategy"] == "web"


def test_ctf_flag_seeds_ctf_strategy():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    orchestrator.run_mission(session=session, target=target, objective="", metadata={"ctf": True})

    assert captured["state"].metadata["strategy"] == "ctf"
    # Caller metadata is preserved alongside the strategy hint.
    assert captured["state"].metadata["ctf"] is True


def test_caller_metadata_wins_over_strategy_defaults():
    captured: dict = {}
    orchestrator = _orchestrator_with_capture(captured)
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    orchestrator.run_mission(
        session=session,
        target=target,
        objective="",
        metadata={"strategy": "caller-override"},
    )

    assert captured["state"].metadata["strategy"] == "caller-override"
