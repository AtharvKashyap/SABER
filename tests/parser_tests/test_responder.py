from pathlib import Path

from saber.parsers.responder import ResponderParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_responder_output.txt")


def test_responder_emits_credential_per_capture_and_grows_state():
    result = ResponderParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    credentials = [o for o in obs if o["kind"] == "credential"]
    assert len(credentials) == 2

    smb = next(o for o in credentials if o["data"]["service"] == "smb")
    assert_observation(
        smb,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "kind": "hash",
            "host": "192.168.56.105",
            "service": "smb",
            "validated": False,
        },
    )
    assert smb["data"]["secret"].startswith("jdoe::LAB:")
    assert smb["metadata"]["domain"] == "LAB"

    state = merge_observations(obs, tool="responder", action="listen")
    assert len(state.credentials) == 2
    assert all(c.validated is False for c in state.credentials)
    assert all(c.kind == "hash" for c in state.credentials)


def test_responder_emits_note_per_poisoned_answer():
    result = ResponderParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    notes = [o for o in obs if o["kind"] == "note"]
    assert len(notes) == 2
    titles = {o["data"]["title"] for o in notes}
    assert "LLMNR answer poisoned for 192.168.56.105 (fileserver)" in titles

    state = merge_observations(obs, tool="responder", action="listen")
    assert len(state.notes) == 2


def test_responder_interleaved_protocol_blocks_do_not_cross_contaminate():
    text = "\n".join(
        [
            "[SMB] NTLMv2-SSP Client   : 10.0.0.1",
            "[HTTP] NTLMv2 Client   : 10.0.0.2",
            "[SMB] NTLMv2-SSP Username : LAB\\alice",
            "[HTTP] NTLMv2 Username : LAB\\bob",
            "[SMB] NTLMv2-SSP Hash     : alice::LAB:11:AA:01",
            "[HTTP] NTLMv2 Hash     : bob::LAB:22:BB:02",
        ]
    )
    result = ResponderParser().parse_text(text)
    by_user = {o.data["username"]: o.data for o in result.observations}
    assert by_user["alice"]["host"] == "10.0.0.1"
    assert by_user["bob"]["host"] == "10.0.0.2"


def test_responder_skips_duplicate_captures():
    line_block = [
        "[SMB] NTLMv2-SSP Client   : 10.0.0.1",
        "[SMB] NTLMv2-SSP Username : LAB\\alice",
        "[SMB] NTLMv2-SSP Hash     : alice::LAB:11:AA:01",
    ]
    result = ResponderParser().parse_text("\n".join(line_block * 2))
    assert len([o for o in result.observations if o.kind == "credential"]) == 1


def test_responder_incomplete_block_emits_nothing():
    text = "[SMB] NTLMv2-SSP Client   : 10.0.0.1\n[SMB] NTLMv2-SSP Username : LAB\\alice\n"
    result = ResponderParser().parse_text(text)
    assert result.observations == []


def test_responder_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "banner only, no captures"):
        result = ResponderParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
