from saber.models.target import Target, TargetType
from saber.tools.active_directory.bloodhound import CONTRACT, BloodHoundWrapper


def _target():
    return Target(type=TargetType.DOMAIN, value="lab.local")


def test_collect_command_passes_password_by_env_var_not_value():
    wrapper = BloodHoundWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="collect", domain="lab.local", username="jdoe")

    assert cmd.command == [
        "bloodhound-python",
        "-d",
        "lab.local",
        "-u",
        "jdoe",
        "-p",
        "$AD_PASSWORD",
        "-c",
        "DCOnly,Group,LocalAdmin,Session,Trusts",
        "--zip",
        "-op",
        "bloodhound",
    ]
    # The secret itself must never appear in the command line.
    assert "$AD_PASSWORD" in cmd.command
    assert cmd.environment == {"AD_PASSWORD": ""}


def test_collect_optional_nameserver_and_dc_host_are_appended():
    wrapper = BloodHoundWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="collect",
        domain="lab.local",
        username="jdoe",
        nameserver="10.0.0.1",
        dc_host="dc01.lab.local",
    )
    assert cmd.command[-4:] == ["-ns", "10.0.0.1", "-dc", "dc01.lab.local"]


def test_ingest_existing_zip_is_not_offered_to_the_decider():
    """The wrapper still implements it, but it must not be advertised.

    Its command is ["python", "-m", "saber.parsers.bloodhound", ...], which cannot run:
    Kali has no `python` alias, the saber package is not installed in the sandbox
    image, and that module has no __main__. Offering it guarantees a failed step.
    Collection output is parsed by BloodHoundParser through the parser registry, which
    needs no subprocess at all.
    """

    assert "ingest_existing_zip" not in {a.action for a in CONTRACT.actions}

    # The method is retained for whoever fixes the producer.
    wrapper = BloodHoundWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="ingest_existing_zip", zip_path="/tmp/saber/bloodhound.zip"
    )
    assert cmd.command[0] == "python"


def test_missing_required_arg_raises_value_error_not_key_error():
    wrapper = BloodHoundWrapper(sandbox=None)
    for kwargs in ({}, {"domain": "lab.local"}):
        try:
            wrapper.build_command(_target(), action="collect", **kwargs)
        except ValueError as exc:
            assert "is required" in str(exc)
        else:
            raise AssertionError("expected ValueError for a missing required arg")


def test_contract_risk_matches_what_each_action_actually_does():
    by_action = {a.action: a for a in CONTRACT.actions}

    # Authenticated domain-wide collection — the only declared action.
    assert set(by_action) == {"collect"}
    assert by_action["collect"].risk == "high"
    assert by_action["collect"].requires_approval is True
