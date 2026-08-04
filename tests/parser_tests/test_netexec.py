from pathlib import Path

from saber.parsers.netexec import NetExecParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_netexec_output.txt")


def test_netexec_emits_validated_credential_and_admin_session_on_pwn3d():
    result = NetExecParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    credentials = [o for o in obs if o["kind"] == "credential"]
    assert len(credentials) == 2

    smb_cred = next(o for o in credentials if o["data"]["service"] == "smb")
    assert_observation(
        smb_cred,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "secret": "Passw0rd!",
            "kind": "password",
            "host": "10.0.0.5",
            "service": "smb",
            "validated": True,
        },
    )
    assert smb_cred["metadata"]["domain"] == "LAB"
    assert smb_cred["metadata"]["pwned"] is True

    ldap_cred = next(o for o in credentials if o["data"]["service"] == "ldap")
    assert ldap_cred["metadata"]["pwned"] is False

    sessions = [o for o in obs if o["kind"] == "session"]
    assert len(sessions) == 1
    assert_observation(
        sessions[0],
        kind="session",
        data_subset={"host": "10.0.0.5", "user": "jdoe", "privilege": "admin"},
    )

    state = merge_observations(obs, tool="netexec", action="smb_auth_check")
    assert len(state.credentials) == 2
    assert any(c.validated is True for c in state.credentials)
    assert len(state.sessions) == 1
    assert state.sessions[0].privilege == "admin"


def test_netexec_emits_share_per_row_with_explicit_permissions_and_grows_state():
    result = NetExecParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    shares = [o for o in obs if o["kind"] == "share"]
    # ADMIN$, C$, NETLOGON, SYSVOL each list explicit permissions; IPC$ (no
    # permissions column) and the header/separator rows are not shares.
    assert len(shares) == 4
    names = {o["data"]["name"] for o in shares}
    assert names == {"ADMIN$", "C$", "NETLOGON", "SYSVOL"}

    admin_share = next(o for o in shares if o["data"]["name"] == "ADMIN$")
    assert_observation(
        admin_share,
        kind="share",
        data_subset={"host": "10.0.0.5", "name": "ADMIN$", "type": "smb", "access": "write"},
    )

    netlogon = next(o for o in shares if o["data"]["name"] == "NETLOGON")
    assert netlogon["data"]["access"] == "read"

    state = merge_observations(obs, tool="netexec", action="smb_shares")
    assert len(state.shares) == 4


def test_netexec_emits_account_per_ldap_user_row_and_grows_state():
    result = NetExecParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    accounts = [o for o in obs if o["kind"] == "account"]
    assert len(accounts) == 4
    usernames = {o["data"]["username"] for o in accounts}
    assert usernames == {"Administrator", "krbtgt", "jdoe", "asmith"}

    assert_observation(
        accounts[0],
        kind="account",
        data_subset={"source": "netexec", "enabled": True},
    )

    state = merge_observations(obs, tool="netexec", action="ldap_users")
    assert len(state.accounts) == 4


def test_netexec_skips_duplicate_auth_lines():
    text = "\n".join(
        [
            r"SMB   10.0.0.5   445   DC01   [+] LAB\jdoe:Passw0rd! (Pwn3d!)",
            r"SMB   10.0.0.5   445   DC01   [+] LAB\jdoe:Passw0rd! (Pwn3d!)",
        ]
    )
    result = NetExecParser().parse_text(text)
    assert len([o for o in result.observations if o.kind == "credential"]) == 1
    assert len([o for o in result.observations if o.kind == "session"]) == 1


def test_netexec_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "banner only, no useful output"):
        result = NetExecParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
