from saber.models.target import Target, TargetType
from saber.tools.post_exploit.linpeas import CONTRACT, LinpeasWrapper


def _target():
    return Target(type=TargetType.IP, value="10.0.0.9")


def test_run_local_command_uses_the_default_script_path():
    wrapper = LinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_local")
    assert cmd.command == ["bash", "/opt/peas/linpeas.sh"]
    assert cmd.requires_explicit_authorization is True


def test_run_local_quiet_appends_dash_q():
    wrapper = LinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_local", quiet=True)
    assert cmd.command == ["bash", "/opt/peas/linpeas.sh", "-q"]


def test_run_with_output_defaults_the_output_file():
    wrapper = LinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_with_output")
    assert cmd.command == ["bash", "-lc", "bash /opt/peas/linpeas.sh | tee linpeas.out"]


def test_declared_defaults_are_actually_applied_not_raised():
    """A contract that advertises a default while the wrapper raises is drift."""

    wrapper = LinpeasWrapper(sandbox=None)
    for action in CONTRACT.actions:
        # Deliberately pass NO args at all, not even the declared optionals.
        cmd = wrapper.build_command(_target(), action=action.action)
        assert cmd.command, action.action
        assert "/opt/peas/linpeas.sh" in " ".join(cmd.command)


def test_contract_matches_wrapper_category_and_phase():
    wrapper = LinpeasWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_every_action_is_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high", action.action
        assert action.requires_approval is True, action.action
