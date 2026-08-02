"""Golden-command and contract tests for the nuclei wrapper (F1.3)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.web.nuclei import NucleiWrapper


def test_template_scan_command_includes_severity():
    wrapper = NucleiWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(
        target, action="template_scan", severity="low,medium,high,critical"
    )
    assert cmd.command == [
        "nuclei",
        "-nc",
        "-u",
        "127.0.0.1",
        "-severity",
        "low,medium,high,critical",
    ]
    assert cmd.action == "template_scan"
