from pathlib import Path

from saber.parsers.hashcat import HashcatParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_hashcat_output.txt")


def test_hashcat_emits_credential_for_bare_hash_line_with_derived_username():
    result = HashcatParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    ntlm_cred = next(
        o for o in obs if o["metadata"]["hash"] == "b4b9b02e6f09a9bd760f388b67351e2b"
    )
    assert_observation(
        ntlm_cred,
        kind="credential",
        data_subset={
            "username": "hash:b4b9b02e6f09",
            "secret": "Summer2024!",
            "kind": "password",
            "validated": False,
        },
    )


def test_hashcat_emits_credential_for_netntlmv2_line_with_embedded_account():
    result = HashcatParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    netntlm_cred = next(o for o in obs if o["data"]["username"] == "jdoe")
    assert_observation(
        netntlm_cred,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "secret": "Fall2024!",
            "kind": "password",
            "validated": False,
        },
    )
    assert netntlm_cred["metadata"]["domain"] == "LAB"


def test_hashcat_skips_duplicate_cracked_lines():
    result = HashcatParser().parse_text(_FIXTURE.read_text())
    assert len(result.observations) == 2


def test_hashcat_grows_state_credentials():
    result = HashcatParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]
    state = merge_observations(obs, tool="hashcat", action="dictionary_attack")
    assert len(state.credentials) == 2
    assert all(c.validated is False for c in state.credentials)


def test_hashcat_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "no colon at all here", "hashcat (v6.2.6) starting in show mode"):
        result = HashcatParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
