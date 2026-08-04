from saber.core.state_merger import StateMerger
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType


def _merge(obs):
    st = MissionState(session_id="s", target=Target(type=TargetType.IP, value="127.0.0.1"))
    at = AttemptedAction(tool_name="t", action="a", args={}, success=True)
    return StateMerger().merge(st, obs, at)


def test_merges_share_account_session_loot_flag_note():
    obs = [
        {"kind": "share", "data": {"host": "10.0.0.1", "name": "ADMIN$", "access": "read"}},
        {"kind": "account", "data": {"username": "admin", "domain": "CORP"}},
        {"kind": "session", "data": {"host": "10.0.0.1", "kind": "shell", "user": "svc"}},
        {
            "kind": "loot",
            "data": {
                "description": "id_rsa",
                "kind": "key",
                "path": "/r/.ssh/id_rsa",
                "host": "10.0.0.1",
            },
        },
        {"kind": "flag", "data": {"value": "FLAG{x}"}},
        {"kind": "note", "data": {"title": "obs", "detail": "text"}},
    ]
    st = _merge(obs)
    assert len(st.shares) == 1 and len(st.accounts) == 1 and len(st.sessions) == 1
    assert len(st.loot) == 1 and len(st.flags) == 1 and len(st.notes) == 1


def test_distinct_loot_from_the_same_file_all_survive():
    """One file routinely yields several distinct secrets; none may be dropped.

    The loot key used to be (host, path, kind), so a strings dump that found both
    a connection string and a cloud key in one binary collapsed them into a single
    entry and silently lost the rest. The description is part of the key.
    """

    common = {"path": "/opt/lab/vulnbin", "host": "10.0.0.7", "kind": "config"}
    obs = [
        {"kind": "loot", "data": {"description": "connection string", **common}},
        {"kind": "loot", "data": {"description": "api key", **common}},
        {"kind": "loot", "data": {"description": "cloud access key", **common}},
    ]
    st = _merge(obs)
    assert len(st.loot) == 3
    assert {item.description for item in st.loot} == {
        "connection string",
        "api key",
        "cloud access key",
    }


def test_identical_loot_is_still_deduped():
    obs = [
        {
            "kind": "loot",
            "data": {"description": "id_rsa", "kind": "key", "path": "/r/.ssh/id_rsa"},
        }
    ] * 3
    assert len(_merge(obs).loot) == 1


def test_dedupe_by_key():
    obs = [{"kind": "flag", "data": {"value": "FLAG{x}"}}] * 3
    assert len(_merge(obs).flags) == 1
