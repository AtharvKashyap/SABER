"""Golden-command and contract tests for the masscan wrapper (F1.7)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.masscan import MasscanWrapper


def test_scan_ports_command():
    wrapper = MasscanWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="scan_ports", ports="80,443,445,3389,22", rate=1000)
    assert cmd.command == [
        "masscan",
        "127.0.0.1",
        "-p",
        "80,443,445,3389,22",
        "--rate",
        "1000",
    ]
    assert cmd.action == "scan_ports"
