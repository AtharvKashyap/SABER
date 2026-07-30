from saber.models.target import Target, TargetType
from saber.tools.password.hashcat import CONTRACT, HashcatWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def _wrapper():
    return HashcatWrapper(sandbox=None)


def test_dictionary_attack_command():
    cmd = _wrapper().build_command(
        _target(),
        action="dictionary_attack",
        hash_file="/data/hashes.txt",
        hash_mode="1000",
        wordlist="/wordlists/rockyou.txt",
    )
    assert cmd.command == [
        "hashcat",
        "-m",
        "1000",
        "-a",
        "0",
        "/data/hashes.txt",
        "/wordlists/rockyou.txt",
    ]
    assert cmd.action == "dictionary_attack"


def test_dictionary_attack_command_with_rules_and_workload_profile():
    cmd = _wrapper().build_command(
        _target(),
        action="dictionary_attack",
        hash_file="/data/hashes.txt",
        hash_mode="1000",
        wordlist="/wordlists/rockyou.txt",
        rules=["/rules/best64.rule", "/rules/toggles.rule"],
        workload_profile=3,
    )
    assert cmd.command == [
        "hashcat",
        "-m",
        "1000",
        "-a",
        "0",
        "/data/hashes.txt",
        "/wordlists/rockyou.txt",
        "-r",
        "/rules/best64.rule",
        "-r",
        "/rules/toggles.rule",
        "-w",
        "3",
    ]


def test_mask_attack_command():
    cmd = _wrapper().build_command(
        _target(),
        action="mask_attack",
        hash_file="/data/hashes.txt",
        hash_mode="1000",
        mask="?u?l?l?l?l?d?d",
    )
    assert cmd.command == [
        "hashcat",
        "-m",
        "1000",
        "-a",
        "3",
        "/data/hashes.txt",
        "?u?l?l?l?l?d?d",
    ]
    assert cmd.action == "mask_attack"


def test_show_cracked_command():
    cmd = _wrapper().build_command(
        _target(), action="show_cracked", hash_file="/data/hashes.txt", hash_mode="1000"
    )
    assert cmd.command == ["hashcat", "-m", "1000", "--show", "/data/hashes.txt"]
    assert cmd.action == "show_cracked"


def test_benchmark_command_without_hash_mode():
    cmd = _wrapper().build_command(_target(), action="benchmark")
    assert cmd.command == ["hashcat", "-b"]
    assert cmd.action == "benchmark"


def test_benchmark_command_with_hash_mode():
    cmd = _wrapper().build_command(_target(), action="benchmark", hash_mode="1000")
    assert cmd.command == ["hashcat", "-b", "-m", "1000"]


def test_unsupported_action_raises():
    try:
        _wrapper().build_command(_target(), action="bogus")
    except ValueError as exc:
        assert "Unsupported Hashcat action" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported action")


def test_contract_declares_all_four_dispatch_branches():
    assert {a.action for a in CONTRACT.actions} == {
        "dictionary_attack",
        "mask_attack",
        "show_cracked",
        "benchmark",
    }


def test_contract_marks_cracking_actions_medium_risk_and_approval_gated():
    for action_name in ("dictionary_attack", "mask_attack"):
        action = next(a for a in CONTRACT.actions if a.action == action_name)
        assert action.risk == "medium"
        assert action.requires_approval is True


def test_contract_marks_local_read_actions_low_risk_and_autonomous():
    for action_name in ("show_cracked", "benchmark"):
        action = next(a for a in CONTRACT.actions if a.action == action_name)
        assert action.risk == "low"
        assert action.requires_approval is False


def test_benchmark_declares_no_credential_emission():
    benchmark = next(a for a in CONTRACT.actions if a.action == "benchmark")
    assert benchmark.emits_kinds == ()


def test_cracking_and_show_actions_declare_credential_emission():
    for action_name in ("dictionary_attack", "mask_attack", "show_cracked"):
        action = next(a for a in CONTRACT.actions if a.action == action_name)
        assert action.emits_kinds == ("credential",)


def test_no_action_declares_a_reserved_arg():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        assert not ({spec.name for spec in action.args} & reserved)
        assert not (set(action.example_args) & reserved)


def test_contract_actions_are_buildable_from_their_own_example_args():
    wrapper = _wrapper()
    for action in CONTRACT.actions:
        command = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert command.command
