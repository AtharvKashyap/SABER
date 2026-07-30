from pathlib import Path

from saber.parsers.impacket import ImpacketParser

from tests.conftest import assert_observation, merge_observations

_AD_USERS = Path("tests/fixtures/sample_impacket_get_ad_users_output.txt")
_GET_SPNS = Path("tests/fixtures/sample_impacket_get_spns_output.txt")
_ASREP = Path("tests/fixtures/sample_impacket_get_asrep_output.txt")
_SMB_EXEC = Path("tests/fixtures/sample_impacket_smb_exec_output.txt")


def test_get_ad_users_emits_account_per_row_and_grows_state():
    result = ImpacketParser().parse_text(_AD_USERS.read_text())
    obs = [o.to_dict() for o in result.observations]

    accounts = [o for o in obs if o["kind"] == "account"]
    assert len(accounts) == 3
    usernames = {a["data"]["username"] for a in accounts}
    assert usernames == {"alice", "bob", "krbtgt"}

    alice = next(a for a in accounts if a["data"]["username"] == "alice")
    assert_observation(
        alice,
        kind="account",
        data_subset={
            "username": "alice",
            "domain": "corp.local",
            "source": "impacket_get_ad_users",
            "enabled": True,
        },
    )

    state = merge_observations(obs, tool="impacket", action="get_ad_users")
    assert len(state.accounts) == 3


def test_get_spns_emits_credential_hash_and_grows_state():
    result = ImpacketParser().parse_text(_GET_SPNS.read_text())
    obs = [o.to_dict() for o in result.observations]

    credentials = [o for o in obs if o["kind"] == "credential"]
    assert len(credentials) == 1
    assert_observation(
        credentials[0],
        kind="credential",
        data_subset={
            "username": "svcsql",
            "kind": "hash",
            "service": "kerberos",
            "validated": False,
        },
    )
    assert credentials[0]["data"]["secret"].startswith("$krb5tgs$23$*svcsql$CORP.LOCAL$")
    assert credentials[0]["metadata"]["domain"] == "CORP.LOCAL"

    state = merge_observations(obs, tool="impacket", action="get_spns")
    assert len(state.credentials) == 1
    assert state.credentials[0].validated is False
    assert state.credentials[0].kind == "hash"


def test_get_asrep_candidates_emits_credential_hash_and_grows_state():
    result = ImpacketParser().parse_text(_ASREP.read_text())
    obs = [o.to_dict() for o in result.observations]

    credentials = [o for o in obs if o["kind"] == "credential"]
    assert len(credentials) == 1
    assert_observation(
        credentials[0],
        kind="credential",
        data_subset={"username": "alice", "kind": "hash", "validated": False},
    )
    assert credentials[0]["data"]["secret"].startswith("$krb5asrep$23$alice@CORP.LOCAL:")

    state = merge_observations(obs, tool="impacket", action="get_asrep_candidates")
    assert len(state.credentials) == 1


def test_smb_exec_check_emits_session_on_confirmed_foothold_and_grows_state():
    result = ImpacketParser().parse_text(_SMB_EXEC.read_text(), metadata={"target": "10.0.0.5"})
    obs = [o.to_dict() for o in result.observations]

    sessions = [o for o in obs if o["kind"] == "session"]
    assert len(sessions) == 1
    assert_observation(
        sessions[0],
        kind="session",
        data_subset={"host": "10.0.0.5", "kind": "shell", "user": "administrator"},
    )
    assert sessions[0]["metadata"]["domain"] == "CORP"

    state = merge_observations(obs, tool="impacket", action="smb_exec_check")
    assert len(state.sessions) == 1


def test_smb_exec_check_without_service_start_marker_emits_nothing():
    text = "\n".join(
        [
            "[*] Requesting shares on 10.0.0.5.....",
            "[-] Could not open service manager: access denied",
        ]
    )
    result = ImpacketParser().parse_text(text)
    assert result.observations == []


def test_duplicate_spn_hash_lines_are_deduplicated():
    text = _GET_SPNS.read_text()
    result = ImpacketParser().parse_text(text + "\n" + text)
    assert len([o for o in result.observations if o.kind == "credential"]) == 1


def test_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "Impacket v0.11.0 - Copyright 2023 Fortra\n[*] no useful output"):
        result = ImpacketParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
