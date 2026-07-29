"""Golden-command and contract tests for the nikto wrapper (F1.4)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.web.nikto import NiktoWrapper


def test_web_scan_command_includes_port():
    wrapper = NiktoWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="web_scan", port="8080")
    assert cmd.command == ["nikto", "-h", "127.0.0.1", "-p", "8080"]
    assert cmd.action == "web_scan"


def test_web_scan_command_without_port():
    wrapper = NiktoWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="web_scan")
    assert cmd.command == ["nikto", "-h", "127.0.0.1"]
