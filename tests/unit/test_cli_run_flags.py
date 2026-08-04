from unittest.mock import patch

from saber.ui.cli import main as cli_main


def _dispatch(argv):
    parser = cli_main.build_parser()
    args = parser.parse_args(argv)
    with patch.object(cli_main, "run_cli_mission", return_value={}) as run:
        cli_main.dispatch(args, None, None, None)
    return run


def test_strategy_and_lab_and_scope_flags_are_passed():
    run = _dispatch(
        ["run", "--target", "dvwa", "--profile", "web",
         "--strategy", "ctf", "--lab", "--scope", "runs/lab_scope.yaml"]
    )
    _, kwargs = run.call_args
    assert kwargs["strategy"] == "ctf"
    assert kwargs["lab"] is True
    assert kwargs["scope_path"] == "runs/lab_scope.yaml"


def test_defaults_when_flags_absent():
    run = _dispatch(["run", "--target", "127.0.0.1"])
    _, kwargs = run.call_args
    assert kwargs["strategy"] == "auto"
    assert kwargs["lab"] is False
    assert kwargs["scope_path"] is None
