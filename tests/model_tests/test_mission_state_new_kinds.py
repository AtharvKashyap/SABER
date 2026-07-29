from saber.models.mission_state import (
    KnownAccount,
    KnownFlag,
    KnownLoot,
    KnownSession,
    KnownShare,
    MissionNote,
    MissionState,
)
from saber.models.target import Target, TargetType


def _target() -> Target:
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_new_lists_default_empty_and_counts_present():
    st = MissionState(session_id="s", target=_target())
    assert st.shares == [] and st.accounts == [] and st.sessions == []
    assert st.loot == [] and st.flags == [] and st.notes == []
    counts = st.to_summary_dict()["counts"]
    for key in ("shares", "accounts", "sessions", "loot", "flags", "notes"):
        assert counts[key] == 0


def test_new_models_construct():
    KnownShare(host="10.0.0.1", name="ADMIN$", type="smb", access="read")
    KnownAccount(username="admin", domain="CORP")
    KnownSession(host="10.0.0.1", kind="shell", privilege="user")
    KnownLoot(description="id_rsa", kind="key", host="10.0.0.1", path="/root/.ssh/id_rsa")
    KnownFlag(value="FLAG{x}")
    MissionNote(title="note", detail="d")
