"""Web mission-start tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from saber.ui.web.app import create_app


def test_dashboard_contains_start_mission_form(tmp_path) -> None:
    app = create_app(
        db_path=tmp_path / "saber.db",
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )

    client = TestClient(app)
    response = client.get("/ui")

    assert response.status_code == 200
    assert "Start mission" in response.text
    assert "mission-start-form" in response.text
    assert "/sessions/run" in response.text
    # Every field the run endpoint accepts is reachable from the form.
    for field in (
        "target",
        "profile",
        "strategy",
        "agent_mode",
        "max_steps",
        "objective",
        "mission_name",
        "require_approval",
        "dry_run",
        "lab",
    ):
        assert f'id="{field}"' in response.text, f"missing form field: {field}"


def test_sessions_run_endpoint_starts_background_mission(monkeypatch, tmp_path) -> None:
    calls = []

    class ImmediateThread:
        def __init__(self, target, kwargs, daemon=True):
            self.target = target
            self.kwargs = kwargs
            self.daemon = daemon

        def start(self):
            self.target(**self.kwargs)

    def fake_run_cli_mission(**kwargs):
        calls.append(kwargs)
        return {
            "session_id": kwargs["session_id"],
            "status": "completed",
        }

    import saber.ui.web.routers.sessions as sessions_router

    monkeypatch.setattr(sessions_router, "Thread", ImmediateThread)
    monkeypatch.setattr(sessions_router, "run_cli_mission", fake_run_cli_mission)

    app = create_app(
        db_path=tmp_path / "saber.db",
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )

    client = TestClient(app)
    response = client.post(
        "/sessions/run",
        json={
            "target": "127.0.0.1",
            "profile": "recon",
            "objective": "Run safe recon.",
            "max_steps": 5,
            "require_approval": True,
            "dry_run": True,
            "agent_mode": "deterministic",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "started"
    assert data["session_id"].startswith("session_")
    assert data["detail_url"] == f"/ui/sessions/{data['session_id']}"
    assert calls
    assert calls[0]["session_id"] == data["session_id"]
    assert calls[0]["target_value"] == "127.0.0.1"
    assert calls[0]["profile"] == "recon"
    assert calls[0]["max_steps"] == 5
    assert calls[0]["dry_run"] is True
