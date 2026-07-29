"""Golden-command and contract tests for the nmap wrapper (F1.1)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.nmap import NmapWrapper


def test_service_scan_command_includes_pn():
    wrapper = NmapWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="service_scan", ports="1-1000")
    assert cmd.command == ["nmap", "-sT", "-sV", "-sC", "-Pn", "-p", "1-1000", "127.0.0.1"]
    assert cmd.action == "service_scan"
