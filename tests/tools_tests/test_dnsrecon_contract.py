"""Golden-command and contract tests for the dnsrecon wrapper (F1.7)."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.recon.dnsrecon import DNSReconWrapper


def test_standard_command():
    wrapper = DNSReconWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.DOMAIN, value="example.com")
    cmd = wrapper.build_command(target, action="standard")
    assert cmd.command == ["dnsrecon", "-d", "example.com", "-t", "std"]
    assert cmd.action == "standard"
