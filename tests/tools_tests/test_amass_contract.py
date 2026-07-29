"""Golden-command and contract tests for the amass wrapper (F1.7)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.amass import AmassWrapper


def test_passive_enum_command():
    wrapper = AmassWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.DOMAIN, value="example.com")
    cmd = wrapper.build_command(target, action="passive_enum")
    assert cmd.command == ["amass", "enum", "-passive", "-d", "example.com"]
    assert cmd.action == "passive_enum"
