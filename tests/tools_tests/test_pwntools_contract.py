from saber.models.target import Target, TargetType
from saber.tools.registry import build_default_registry
from saber.tools.reverse_engineering.pwntools import CONTRACT, PwntoolsWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_run_exploit_runs_the_script_with_python3_not_bash():
    """pwntools scripts are Python; custom_cli.run_script uses bash and cannot run them."""

    wrapper = PwntoolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="run_exploit",
        binary_path="/opt/lab/vulnbin",
        script_path="/workspace/tmp/exploit.py",
    )

    assert cmd.command == ["python3", "/workspace/tmp/exploit.py", "/opt/lab/vulnbin"]
    assert cmd.requires_explicit_authorization is True


def test_run_exploit_appends_extra_argv_after_the_binary():
    wrapper = PwntoolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="run_exploit",
        binary_path="/opt/lab/vulnbin",
        script_path="/workspace/tmp/exploit.py",
        argv=["--offset", "72"],
    )

    assert cmd.command == [
        "python3",
        "/workspace/tmp/exploit.py",
        "/opt/lab/vulnbin",
        "--offset",
        "72",
    ]


def test_run_exploit_ignores_blank_argv_entries():
    wrapper = PwntoolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="run_exploit",
        binary_path="/opt/lab/vulnbin",
        script_path="/workspace/tmp/exploit.py",
        argv=["", "  ", "72"],
    )
    assert cmd.command[-1] == "72"
    assert "" not in cmd.command


def test_debug_without_a_script_just_runs_the_binary_in_batch_mode():
    wrapper = PwntoolsWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="debug", binary_path="/opt/lab/vulnbin")
    assert cmd.command == ["gdb", "--batch", "/opt/lab/vulnbin"]


def test_debug_with_a_script_passes_it_via_dash_x():
    wrapper = PwntoolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="debug",
        binary_path="/opt/lab/vulnbin",
        gdb_script="/workspace/tmp/find_offset.gdb",
    )
    assert cmd.command == [
        "gdb",
        "--batch",
        "-x",
        "/workspace/tmp/find_offset.gdb",
        "/opt/lab/vulnbin",
    ]


def test_missing_required_args_raise_value_error():
    wrapper = PwntoolsWrapper(sandbox=None)
    for kwargs in (
        {},  # no binary_path
        {"binary_path": "/opt/lab/vulnbin"},  # no script_path
    ):
        try:
            wrapper.build_command(_target(), action="run_exploit", **kwargs)
        except ValueError as exc:
            assert "is required" in str(exc)
        else:
            raise AssertionError("expected ValueError for a missing required arg")


def test_unsupported_action_raises():
    wrapper = PwntoolsWrapper(sandbox=None)
    try:
        wrapper.build_command(_target(), action="solve_it_for_me", binary_path="/x")
    except ValueError as exc:
        assert "Unsupported pwntools action" in str(exc)
    else:
        raise AssertionError("expected ValueError for an unknown action")


def test_every_declared_action_builds_from_its_example_args():
    wrapper = PwntoolsWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command, action.action


def test_contract_matches_wrapper_category_and_phase():
    wrapper = PwntoolsWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_binary_exploitation_is_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high", action.action
        assert action.requires_approval is True, action.action


def test_both_actions_can_yield_a_flag_or_a_note():
    for action in CONTRACT.actions:
        assert set(action.emits_kinds) == {"flag", "note"}, action.action


def test_pwntools_is_registered_and_loadable():
    entry = build_default_registry().get("pwntools")
    assert entry.load_class() is PwntoolsWrapper
    assert entry.load_contract() is CONTRACT


def test_pwntools_is_reachable_under_its_aliases():
    registry = build_default_registry()
    for alias in ("pwn", "gdb"):
        assert registry.get(alias).name == "pwntools"
