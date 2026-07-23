from unittest.mock import patch

from fastapi.testclient import TestClient

from saber.ui.web import app as web_app


def _client():
    application = web_app.create_app(require_auth=False)
    return TestClient(application)


def test_run_passes_strategy_and_lab_to_run_cli_mission():
    with patch("saber.ui.web.routers.sessions.run_cli_mission", return_value={}) as run:
        # Thread target is started but we only assert the kwargs it was built with.
        with patch("saber.ui.web.routers.sessions.Thread") as thread:
            client = _client()
            resp = client.post(
                "/sessions/run",
                json={"target": "dvwa", "profile": "web", "strategy": "ctf", "lab": True},
            )
    assert resp.status_code == 200
    kwargs = thread.call_args.kwargs["kwargs"]
    assert kwargs["strategy"] == "ctf"
    assert kwargs["lab"] is True
    assert run is not None
