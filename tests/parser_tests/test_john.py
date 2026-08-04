from pathlib import Path

from saber.parsers.john import JohnParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_john_output.txt")


def test_john_show_emits_unvalidated_credential_per_cracked_line_and_grows_state():
    result = JohnParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    credentials = [o for o in obs if o["kind"] == "credential"]
    assert len(credentials) == 3
    usernames = {o["data"]["username"] for o in credentials}
    assert usernames == {"jdoe", "asmith", "svc_backup"}

    jdoe = next(o for o in credentials if o["data"]["username"] == "jdoe")
    assert_observation(
        jdoe,
        kind="credential",
        data_subset={
            "username": "jdoe",
            "secret": "Summer2023!",
            "kind": "password",
            "validated": False,
        },
    )

    state = merge_observations(obs, tool="john", action="show_cracked")
    assert len(state.credentials) == 3
    assert all(c.validated is False for c in state.credentials)


def test_john_show_summary_line_never_becomes_a_credential():
    text = "jdoe:Summer2023!\n\n1 password hash cracked, 0 left\n"
    result = JohnParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    assert len(obs) == 1
    assert obs[0]["data"]["username"] == "jdoe"


def test_john_skips_duplicate_usernames():
    text = "jdoe:Summer2023!\njdoe:Summer2023!\n"
    result = JohnParser().parse_text(text)
    assert len(result.observations) == 1


def test_john_skips_uncracked_entries_with_empty_secret():
    text = "jdoe:\nasmith:Passw0rd!\n"
    result = JohnParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    assert len(obs) == 1
    assert obs[0]["data"]["username"] == "asmith"


def test_john_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "No password hashes loaded\n", "2 password hashes cracked, 0 left\n"):
        result = JohnParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
