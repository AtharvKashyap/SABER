"""Golden-command and contract tests for the searchsploit wrapper (F1.6)."""

from __future__ import annotations

from saber.tools.exploitation.searchsploit import SearchSploitWrapper


def test_exploit_search_command():
    wrapper = SearchSploitWrapper(sandbox=None)  # build_command does not touch sandbox
    cmd = wrapper.build_command(action="exploit_search", query="Apache 2.4.49")
    assert cmd.command == ["searchsploit", "--json", "Apache 2.4.49"]
    assert cmd.action == "exploit_search"


def test_exploit_search_command_options():
    wrapper = SearchSploitWrapper(sandbox=None)
    cmd = wrapper.build_command(
        action="exploit_search",
        query="OpenSSH",
        json_output=False,
        case_sensitive=True,
        exact=True,
    )
    assert cmd.command == ["searchsploit", "--case", "--exact", "OpenSSH"]
