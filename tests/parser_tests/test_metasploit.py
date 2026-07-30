from pathlib import Path

from saber.parsers.metasploit import MetasploitParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_metasploit_output.txt")


def test_metasploit_search_rows_emit_one_note_per_module_and_grow_state():
    result = MetasploitParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    search_notes = [
        o
        for o in obs
        if o["kind"] == "note" and o["data"]["title"].startswith("Metasploit search match:")
    ]
    assert len(search_notes) == 2
    titles = {o["data"]["title"] for o in search_notes}
    assert titles == {
        "Metasploit search match: exploit/windows/smb/ms17_010_eternalblue",
        "Metasploit search match: auxiliary/admin/smb/ms17_010_command",
    }

    state = merge_observations(obs, tool="metasploit", action="search_modules")
    assert len(state.notes) == 4  # 2 search matches + 2 generic "[+]" notes


def test_metasploit_check_module_confirmed_vulnerable_emits_vuln_and_grows_state():
    result = MetasploitParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    vulns = [o for o in obs if o["kind"] == "vuln"]
    assert len(vulns) == 1
    assert_observation(
        vulns[0],
        kind="vuln",
        data_subset={
            "title": "Metasploit: exploit/windows/smb/ms17_010_eternalblue confirmed vulnerable",
            "host": "10.129.42.10",
            "port": 445,
            "severity": "high",
            "identifier": "exploit/windows/smb/ms17_010_eternalblue",
            "confirmed": True,
        },
    )

    state = merge_observations(obs, tool="metasploit", action="check_module")
    assert len(state.vulns) == 1
    assert state.vulns[0].confirmed is True


def test_metasploit_run_module_meterpreter_session_emits_session_and_grows_state():
    result = MetasploitParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    sessions = [o for o in obs if o["kind"] == "session"]
    assert len(sessions) == 1
    assert_observation(
        sessions[0],
        kind="session",
        data_subset={"host": "10.129.42.10", "kind": "meterpreter", "ref": "1"},
    )

    state = merge_observations(obs, tool="metasploit", action="run_module")
    assert len(state.sessions) == 1
    assert state.sessions[0].kind == "meterpreter"
    assert state.sessions[0].ref == "1"


def test_metasploit_generic_plus_lines_emit_notes_and_grow_state():
    result = MetasploitParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    generic_notes = [
        o for o in obs if o["kind"] == "note" and o["data"]["title"].startswith("Metasploit: ")
    ]
    assert len(generic_notes) == 2
    titles = {o["data"]["title"] for o in generic_notes}
    assert titles == {
        "Metasploit: 10.129.42.10:445 - Connection established for exploitation.",
        r"Metasploit: Deleted C:\Windows\Temp\x.exe",
    }


def test_metasploit_duplicate_session_line_deduplicates():
    text = "\n".join(
        [
            "[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.129.42.10:49158) "
            "at 2026-07-29 10:15:00 +0000",
            "[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.129.42.10:49158) "
            "at 2026-07-29 10:15:00 +0000",
        ]
    )
    result = MetasploitParser().parse_text(text)
    assert len([o for o in result.observations if o.kind == "session"]) == 1


def test_metasploit_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "banner only, no useful output", "msf6 >\n[*] just info lines\n"):
        result = MetasploitParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
