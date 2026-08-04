"""Golden-command test for the custom_cli CONTRACT and build_command."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.custom_cli import CustomCliWrapper


def test_run_command_builds_bash_tool_command():
    """build_command(run_command) produces a bash ToolCommand."""

    wrapper = CustomCliWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")

    tool_command = wrapper.build_command(
        target,
        action="run_command",
        command="id",
        reason="test",
    )

    assert tool_command.command[0] == "bash"
    assert tool_command.command == ["bash", "-lc", "id"]
    assert tool_command.action == "run_command"
    assert tool_command.requires_explicit_authorization is True
