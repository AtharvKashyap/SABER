from unittest.mock import MagicMock, patch

from saber.ui.cli import run_command


def _run(**overrides):
    """Call run_cli_mission with build_saber_runtime fully mocked."""
    with patch.object(run_command, "build_saber_runtime") as build:
        runtime = MagicMock()
        runtime.llm_client.enabled = False
        # run_mission returns an object persist_mission_result can consume.
        result = MagicMock()
        result.records = []
        result.observations = []
        result.status.value = "completed"
        runtime.orchestrator.run_mission.return_value = result
        build.return_value = runtime
        with patch.object(run_command, "persist_mission_result"):
            run_command.run_cli_mission(
                target_value="dvwa",
                profile="web",
                agent_mode="deterministic",
                **overrides,
            )
        return runtime.orchestrator.run_mission


def test_strategy_override_reaches_run_mission_metadata():
    run_mission = _run(strategy="ctf")
    _, kwargs = run_mission.call_args
    assert kwargs["metadata"].get("strategy_override") == "ctf"


def test_auto_strategy_sets_no_override():
    run_mission = _run(strategy="auto")
    _, kwargs = run_mission.call_args
    assert "strategy_override" not in kwargs["metadata"]


def test_lab_flag_reaches_metadata():
    run_mission = _run(lab=True)
    _, kwargs = run_mission.call_args
    assert kwargs["metadata"].get("lab") is True
