from pathlib import Path

from saber.parsers.mimikatz import MimikatzParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_mimikatz_output.txt")


def _observations():
    result = MimikatzParser().parse_text(_FIXTURE.read_text())
    return [o.to_dict() for o in result.observations]


def test_mimikatz_emits_ntlm_hash_and_wdigest_plaintext_for_same_user():
    obs = _observations()
    credentials = [o for o in obs if o["kind"] == "credential"]

    jdoe_creds = [c for c in credentials if c["data"]["username"] == "jdoe"]
    # jdoe has an msv NTLM hash and a wdigest plaintext; both must survive as
    # distinct observations (distinct `service`) rather than colliding.
    assert len(jdoe_creds) == 2

    jdoe_hash = next(c for c in jdoe_creds if c["data"]["kind"] == "hash")
    assert_observation(
        jdoe_hash,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "secret": "0123456789abcdef0123456789abcdef",
            "kind": "hash",
            "service": "ntlm",
            "validated": False,
        },
    )

    jdoe_password = next(c for c in jdoe_creds if c["data"]["kind"] == "password")
    assert_observation(
        jdoe_password,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "secret": "Lab-Wdigest-Pass1!",
            "kind": "password",
            "service": "wdigest",
            "validated": False,
        },
    )
    assert jdoe_password["data"]["service"] != jdoe_hash["data"]["service"]


def test_mimikatz_emits_account_per_compromised_user():
    obs = _observations()
    accounts = [o for o in obs if o["kind"] == "account"]

    usernames = {a["data"]["username"] for a in accounts}
    assert usernames == {"jdoe", "svc-backup"}

    jdoe_account = next(a for a in accounts if a["data"]["username"] == "jdoe")
    assert_observation(
        jdoe_account,
        kind="account",
        data_subset={"username": "jdoe", "domain": "CORP", "source": "mimikatz", "enabled": True},
    )


def test_mimikatz_skips_null_passwords():
    obs = _observations()
    credentials = [o for o in obs if o["kind"] == "credential"]

    # svc-backup's wdigest/kerberos entries are both "(null)" in the fixture;
    # only its NTLM hash should have been captured.
    svc_creds = [c for c in credentials if c["data"]["username"] == "svc-backup"]
    assert len(svc_creds) == 1
    assert svc_creds[0]["data"]["kind"] == "hash"

    assert len(credentials) == 3


def test_mimikatz_merge_grows_credentials_and_accounts():
    obs = _observations()
    state = merge_observations(obs, tool="mimikatz", action="logonpasswords")

    assert len(state.credentials) == 3
    assert len(state.accounts) == 2

    jdoe_creds = [c for c in state.credentials if c.username == "jdoe"]
    assert len(jdoe_creds) == 2
    assert {c.kind for c in jdoe_creds} == {"hash", "password"}
    assert all(c.validated is False for c in jdoe_creds)


def test_mimikatz_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "no secrets here, just a banner"):
        result = MimikatzParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors


def test_mimikatz_derives_host_from_metadata_target():
    result = MimikatzParser().parse_text(
        _FIXTURE.read_text(), metadata={"target": "10.0.0.9"}
    )
    obs = [o.to_dict() for o in result.observations]
    credentials = [o for o in obs if o["kind"] == "credential"]
    assert credentials
    assert all(c["data"]["host"] == "10.0.0.9" for c in credentials)
