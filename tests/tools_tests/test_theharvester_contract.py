"""Golden-command and contract tests for the theharvester wrapper (F1.7)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.theharvester import TheHarvesterWrapper


def test_search_command():
    wrapper = TheHarvesterWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.DOMAIN, value="example.com")
    cmd = wrapper.build_command(target, action="search", sources="all")
    assert cmd.command == ["theHarvester", "-d", "example.com", "-b", "all"]
    assert cmd.action == "search"
