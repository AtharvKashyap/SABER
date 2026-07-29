"""Golden-command and contract tests for the sqlmap wrapper (F1.6)."""

from __future__ import annotations

from saber.tools.web.sqlmap import SqlmapWrapper


def test_injection_test_command_includes_risk_level_batch():
    wrapper = SqlmapWrapper(sandbox=None)  # build_command does not touch sandbox
    cmd = wrapper.build_command(
        action="injection_test",
        url="https://example.com/item?id=1",
        risk=2,
        level=3,
        batch=True,
    )
    assert cmd.command == [
        "sqlmap",
        "-u",
        "https://example.com/item?id=1",
        "--risk",
        "2",
        "--level",
        "3",
        "--batch",
    ]
    assert cmd.action == "injection_test"


def test_injection_test_command_default_risk_level():
    wrapper = SqlmapWrapper(sandbox=None)
    cmd = wrapper.build_command(action="injection_test", url="https://example.com/item?id=1")
    assert cmd.command == [
        "sqlmap",
        "-u",
        "https://example.com/item?id=1",
        "--risk",
        "1",
        "--level",
        "1",
        "--batch",
    ]
