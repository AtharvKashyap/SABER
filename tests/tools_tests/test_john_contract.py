from saber.models.target import Target, TargetType
from saber.tools.password.john import CONTRACT, JohnWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def _wrapper():
    return JohnWrapper(sandbox=None)


def test_dictionary_attack_command():
    cmd = _wrapper().build_command(
        _target(),
        action="dictionary_attack",
        hash_file="/data/hashes.txt",
        wordlist="/usr/share/wordlists/rockyou.txt",
    )
    assert cmd.command == [
        "john",
        "--wordlist=/usr/share/wordlists/rockyou.txt",
        "/data/hashes.txt",
    ]
    assert cmd.action == "dictionary_attack"


def test_dictionary_attack_command_with_format_and_rules():
    cmd = _wrapper().build_command(
        _target(),
        action="dictionary_attack",
        hash_file="/data/hashes.txt",
        wordlist="/usr/share/wordlists/rockyou.txt",
        format_name="raw-md5",
        rules="Jumbo",
    )
    assert cmd.command == [
        "john",
        "--wordlist=/usr/share/wordlists/rockyou.txt",
        "--format=raw-md5",
        "--rules=Jumbo",
        "/data/hashes.txt",
    ]


def test_single_crack_command():
    cmd = _wrapper().build_command(_target(), action="single_crack", hash_file="/data/hashes.txt")
    assert cmd.command == ["john", "--single", "/data/hashes.txt"]
    assert cmd.action == "single_crack"


def test_single_crack_command_with_format():
    cmd = _wrapper().build_command(
        _target(), action="single_crack", hash_file="/data/hashes.txt", format_name="raw-md5"
    )
    assert cmd.command == ["john", "--single", "--format=raw-md5", "/data/hashes.txt"]


def test_show_cracked_command():
    cmd = _wrapper().build_command(_target(), action="show_cracked", hash_file="/data/hashes.txt")
    assert cmd.command == ["john", "--show", "/data/hashes.txt"]
    assert cmd.action == "show_cracked"


def test_show_cracked_command_with_format():
    cmd = _wrapper().build_command(
        _target(), action="show_cracked", hash_file="/data/hashes.txt", format_name="raw-md5"
    )
    assert cmd.command == ["john", "--show", "--format=raw-md5", "/data/hashes.txt"]


def test_list_formats_command():
    cmd = _wrapper().build_command(_target(), action="list_formats")
    assert cmd.command == ["john", "--list=formats"]
    assert cmd.action == "list_formats"


def test_unsupported_action_raises():
    try:
        _wrapper().build_command(_target(), action="bogus")
    except ValueError as exc:
        assert "Unsupported John action" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported action")


def test_contract_declares_all_four_dispatch_branches():
    assert {a.action for a in CONTRACT.actions} == {
        "dictionary_attack",
        "single_crack",
        "show_cracked",
        "list_formats",
    }


def test_contract_marks_cracking_actions_medium_risk_and_approval_gated():
    for name in ("dictionary_attack", "single_crack"):
        action = next(a for a in CONTRACT.actions if a.action == name)
        assert action.risk == "medium"
        assert action.requires_approval is True


def test_contract_marks_read_only_actions_low_risk_and_autonomous():
    for name in ("show_cracked", "list_formats"):
        action = next(a for a in CONTRACT.actions if a.action == name)
        assert action.risk == "low"
        assert action.requires_approval is False


def test_contract_actions_are_buildable_from_their_own_example_args():
    wrapper = _wrapper()
    for action in CONTRACT.actions:
        command = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert command.command
