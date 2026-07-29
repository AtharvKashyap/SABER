"""Golden-command and contract tests for the subfinder wrapper (F1.7)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.subfinder import SubfinderWrapper


def test_passive_command():
    wrapper = SubfinderWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.DOMAIN, value="example.com")
    cmd = wrapper.build_command(target, action="passive")
    assert cmd.command == ["subfinder", "-d", "example.com", "-silent"]
    assert cmd.action == "passive"
