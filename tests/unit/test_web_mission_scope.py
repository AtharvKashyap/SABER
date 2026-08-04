"""A mission launched from the console must be scoped to its target.

The launch form tells the operator, next to the Target field: "This becomes the
mission scope — anything outside it is refused, not queued for approval." That
was not true. The web route never set a scope, ``MissionSession.scope`` defaulted
to None, and ``RiskGate._scope_allows`` returns True for every action when scope
is None — so a console-launched mission had no scope wall at all, while the UI
said it did.

The CLI is unchanged: it still takes an explicit --scope file, and omitting it
still means unrestricted, which is a deliberate operator choice made at a
terminal. The console has no way to express a scope file, so the target is it.
"""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from saber.ui.web.app import create_app


def _run(payload):
    """POST a mission and return the kwargs handed to run_cli_mission."""

    with (
        patch("saber.ui.web.routers.sessions.run_cli_mission", return_value={}),
        patch("saber.ui.web.routers.sessions.Thread") as thread,
    ):
        client = TestClient(create_app(require_auth=False))
        response = client.post("/sessions/run", json=payload)

    assert response.status_code == 200
    return thread.call_args.kwargs["kwargs"]


def test_web_launch_scopes_the_mission_to_its_target() -> None:
    kwargs = _run({"target": "dvwa", "profile": "web"})

    scope = kwargs.get("scope")
    assert scope is not None, "console-launched mission was left unscoped"
    assert [target.value for target in scope.targets] == ["dvwa"]


def test_the_scope_actually_refuses_a_different_host() -> None:
    """Pin the behaviour the form promises, not just the plumbing."""

    from saber.agents.deciders.base import ActionKind, ProposedAction
    from saber.models.mission_state import MissionState
    from saber.models.target import Target, TargetType
    from saber.orchestration.risk_gate import RiskGate

    scope = _run({"target": "dvwa", "profile": "web"})["scope"]
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.HOST, value="dvwa"),
        scope=scope,
    )

    def action(url: str) -> ProposedAction:
        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name="whatweb",
            tool_action="fingerprint",
            args={"url": url},
            objective="fingerprint",
        )

    assert RiskGate()._scope_allows(state, action("http://dvwa")) is True
    assert RiskGate()._scope_allows(state, action("http://example.com")) is False


def test_a_url_target_is_typed_as_a_url_and_keeps_its_host_and_port() -> None:
    """A URL target used to be typed HOST, which MissionScope rejects outright.

    It also kept `select_strategy` from ever choosing the web strategy under
    `auto`, since that branch tests `target.type == TargetType.URL`.
    """

    from saber.models.target import TargetType

    target = _run({"target": "http://juiceshop:3000", "profile": "web"})["scope"].targets[0]

    assert target.type == TargetType.URL
    # Pydantic normalizes the URL (it appends the root path); the host and port
    # are what scope matching actually compares.
    assert target.value.startswith("http://juiceshop:3000")


def test_auto_strategy_now_reaches_the_web_strategy_for_a_url() -> None:
    from saber.orchestration.strategies.base import select_strategy

    target = _run({"target": "http://juiceshop:3000", "profile": "web"})["scope"].targets[0]

    assert type(select_strategy(target, {})).__name__ == "WebStrategy"
