from saber.models.mission_state import KnownService, MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.storage.connection import StorageConnection
from saber.storage.mission_state_store import MissionStateStore
from saber.storage.session_store import SessionStore


def _conn(tmp_path) -> StorageConnection:
    connection = StorageConnection(tmp_path / "saber.db")
    connection.initialize()
    return connection


def _seed_session(connection) -> str:
    store = SessionStore(connection)
    session = MissionSession(session_id="session_s1", mission_name="m")
    store.create_session(session)
    return session.session_id


def test_migration_003_creates_table(tmp_path):
    connection = _conn(tmp_path)
    row = connection.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='mission_states'"
    )
    assert row is not None


def test_save_and_load_round_trip(tmp_path):
    connection = _conn(tmp_path)
    session_id = _seed_session(connection)
    store = MissionStateStore(connection)

    state = MissionState(
        session_id=session_id,
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
        services=[KnownService(host="10.0.0.5", port=22, service="ssh")],
    )
    store.save(state)

    loaded = store.load(session_id)
    assert loaded is not None
    assert loaded.objective == "assess"
    assert loaded.services[0].key == "10.0.0.5:22/tcp"


def test_save_is_upsert(tmp_path):
    connection = _conn(tmp_path)
    session_id = _seed_session(connection)
    store = MissionStateStore(connection)
    base = MissionState(session_id=session_id, target=Target(type=TargetType.IP, value="10.0.0.5"))

    store.save(base)
    store.save(base.model_copy(update={"objective": "second"}))

    rows = connection.query_all(
        "SELECT session_id FROM mission_states WHERE session_id = ?", (session_id,)
    )
    assert len(rows) == 1
    assert store.load(session_id).objective == "second"


def test_load_missing_returns_none(tmp_path):
    connection = _conn(tmp_path)
    assert MissionStateStore(connection).load("nope") is None
