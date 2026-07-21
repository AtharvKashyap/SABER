"""Integration tests for the live MissionState GUI API endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_state_endpoint_returns_summary(tmp_path) -> None:
    """GET /api/sessions/{id}/state returns summary counts and full service list."""

    from saber.models.mission_state import KnownService, MissionState
    from saber.models.session import MissionSession
    from saber.models.target import Target, TargetType
    from saber.storage.connection import StorageConnection
    from saber.storage.mission_state_store import MissionStateStore
    from saber.storage.session_store import SessionStore
    from saber.ui.web.app import create_app

    db = tmp_path / "saber.db"
    conn = StorageConnection(db)
    conn.initialize()
    SessionStore(conn).create_session(MissionSession(session_id="s1", mission_name="m"))
    MissionStateStore(conn).save(
        MissionState(
            session_id="s1",
            target=Target(type=TargetType.IP, value="10.0.0.5"),
            services=[KnownService(host="10.0.0.5", port=80)],
        )
    )
    conn.close()

    app = create_app(
        db_path=str(db),
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )
    client = TestClient(app)

    resp = client.get("/api/sessions/s1/state")

    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["counts"]["services"] == 1
    assert body["services"][0]["port"] == 80


def test_state_endpoint_unknown_session_returns_404(tmp_path) -> None:
    """GET /api/sessions/{id}/state returns 404 when no state is stored."""

    from saber.ui.web.app import create_app

    db = tmp_path / "saber.db"

    app = create_app(
        db_path=str(db),
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )
    client = TestClient(app)

    resp = client.get("/api/sessions/does-not-exist/state")

    assert resp.status_code == 404


def test_mission_detail_page_includes_live_state_panel(tmp_path) -> None:
    """The mission detail page renders a panel that polls the state endpoint."""

    from saber.models.session import MissionSession
    from saber.storage.connection import StorageConnection
    from saber.storage.session_store import SessionStore
    from saber.ui.web.app import create_app

    db = tmp_path / "saber.db"
    conn = StorageConnection(db)
    conn.initialize()
    SessionStore(conn).create_session(MissionSession(session_id="s1", mission_name="m"))
    conn.close()

    app = create_app(
        db_path=str(db),
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )
    client = TestClient(app)

    resp = client.get("/ui/sessions/s1")

    assert resp.status_code == 200
    text = resp.text
    assert 'id="mission-state-panel"' in text
    # Panel polls the live state endpoint with the page's session id.
    assert '/api/sessions/" + encodeURIComponent(sessionId) + "/state' in text
    assert 'const sessionId = "s1";' in text
