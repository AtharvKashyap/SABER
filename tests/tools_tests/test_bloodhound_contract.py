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


def test_ingest_existing_zip_command():
    wrapper = BloodHoundWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="ingest_existing_zip", zip_path="/tmp/saber/bloodhound.zip"
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.parsers.bloodhound",
        "ingest",
        "/tmp/saber/bloodhound.zip",
    ]
    assert cmd.requires_explicit_authorization is False


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

    # Authenticated domain-wide collection.
    assert by_action["collect"].risk == "high"
    assert by_action["collect"].requires_approval is True
    # Parsing a local zip touches no target.
    assert by_action["ingest_existing_zip"].risk == "low"
    assert by_action["ingest_existing_zip"].requires_approval is False
