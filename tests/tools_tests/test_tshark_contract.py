from saber.models.target import Target, TargetType
from saber.tools.network.tshark import CONTRACT, TsharkWrapper
from saber.tools.registry import build_default_registry


def _target():
    return Target(type=TargetType.CIDR, value="10.0.0.0/24")


def test_capture_command_uses_the_declared_duration_default():
    wrapper = TsharkWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="capture", interface="eth0")

    assert cmd.command == [
        "tshark",
        "-i",
        "eth0",
        "-a",
        "duration:30",
        "-w",
        "/workspace/output/capture.pcap",
    ]
    assert cmd.requires_explicit_authorization is True


def test_capture_appends_a_bpf_filter_when_given():
    wrapper = TsharkWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="capture",
        interface="eth0",
        duration=60,
        capture_filter="tcp port 21",
    )
    assert cmd.command[-2:] == ["-f", "tcp port 21"]
    assert "duration:60" in cmd.command


def test_capture_rejects_a_non_positive_duration():
    wrapper = TsharkWrapper(sandbox=None)
    for bad in (0, -5, "abc"):
        try:
            wrapper.build_command(_target(), action="capture", interface="eth0", duration=bad)
        except ValueError as exc:
            assert "duration must be a positive integer" in str(exc)
        else:
            raise AssertionError(f"expected ValueError for duration={bad!r}")


def test_capture_requires_an_interface():
    wrapper = TsharkWrapper(sandbox=None)
    try:
        wrapper.build_command(_target(), action="capture")
    except ValueError as exc:
        assert "interface is required" in str(exc)
    else:
        raise AssertionError("expected ValueError without an interface")


def test_read_pcap_requests_json_so_the_parser_gets_structure():
    wrapper = TsharkWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="read_pcap", pcap_path="/tmp/x.pcap")
    assert cmd.command == ["tshark", "-r", "/tmp/x.pcap", "-T", "json"]


def test_read_pcap_appends_a_display_filter():
    wrapper = TsharkWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="read_pcap",
        pcap_path="/tmp/x.pcap",
        display_filter="http.authorization",
    )
    assert cmd.command[-2:] == ["-Y", "http.authorization"]


def test_live_capture_is_approval_gated_but_reading_a_pcap_is_not():
    """Capturing observes other hosts' traffic; reading a local file does not."""

    by_action = {action.action: action for action in CONTRACT.actions}

    assert by_action["capture"].risk == "high"
    assert by_action["capture"].requires_approval is True
    assert by_action["read_pcap"].risk == "low"
    assert by_action["read_pcap"].requires_approval is False


def test_reading_a_pcap_needs_no_explicit_authorization_on_the_command():
    wrapper = TsharkWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="read_pcap", pcap_path="/tmp/x.pcap")
    assert cmd.requires_explicit_authorization is False


def test_every_declared_action_builds_from_its_example_args():
    wrapper = TsharkWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command, action.action


def test_contract_matches_wrapper_category_and_phase():
    wrapper = TsharkWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_unsupported_action_raises():
    wrapper = TsharkWrapper(sandbox=None)
    try:
        wrapper.build_command(_target(), action="sniff_everything", interface="eth0")
    except ValueError as exc:
        assert "Unsupported tshark action" in str(exc)
    else:
        raise AssertionError("expected ValueError for an unknown action")


def test_tshark_is_registered_and_loadable_under_its_alias():
    registry = build_default_registry()
    assert registry.get("tshark").load_class() is TsharkWrapper
    assert registry.get("wireshark").name == "tshark"
    assert registry.get("tshark").load_contract() is CONTRACT
