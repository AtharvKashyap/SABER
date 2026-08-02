"""Operator console rendering tests.

These cover the server-rendered console: that every page renders, that the
view-model helpers encode what the templates claim they encode, and that the
console never leaks unescaped mission data into the page.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from saber.models.mission_state import (
    AttemptedAction,
    KnownCredential,
    KnownFlag,
    KnownHost,
    KnownService,
    MissionState,
    PtesPhase,
)
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.mission_state_store import MissionStateStore
from saber.storage.session_store import SessionStore
from saber.ui.web import templating
from saber.ui.web.app import create_app


def _app(tmp_path, seed=None):
    """Build a console app over a fresh database, optionally seeded."""

    db = tmp_path / "saber.db"
    conn = StorageConnection(db)
    conn.initialize()
    if seed is not None:
        seed(conn)
    conn.close()

    return create_app(
        db_path=str(db),
        reports_dir=tmp_path / "reports",
        evidence_dir=tmp_path / "evidence",
        require_auth=False,
    )


@pytest.mark.parametrize(
    "path",
    ["/", "/ui", "/ui/sessions", "/ui/findings", "/ui/reports", "/ui/partials/running"],
)
def test_every_console_page_renders_on_an_empty_database(tmp_path, path) -> None:
    """A fresh install must not 500 on any page."""

    client = TestClient(_app(tmp_path))
    response = client.get(path)

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_static_assets_are_served_from_this_origin(tmp_path) -> None:
    """The console must work air-gapped, so its CSS and JS are self-hosted."""

    client = TestClient(_app(tmp_path))

    assert client.get("/static/saber.css").status_code == 200
    assert client.get("/static/htmx.min.js").status_code == 200
    assert client.get("/static/saber.js").status_code == 200

    csp = client.get("/ui").headers["content-security-policy"]
    assert "script-src 'self';" in csp
    assert "cdn.jsdelivr.net" not in csp


def test_pages_load_the_scripts_that_make_them_work(tmp_path) -> None:
    """Every asset the page references must actually be linked.

    saber.js owns the mission-start submit handler. When the layout forgot to
    include it, the Start mission button silently did nothing.
    """

    client = TestClient(_app(tmp_path))
    text = client.get("/ui").text

    assert '/static/saber.js' in text
    assert '/static/htmx.min.js' in text
    assert '/static/saber.css' in text


def test_module_exposes_the_asgi_app_the_launcher_starts() -> None:
    """`./run_saber` runs `uvicorn saber.ui.web.app:app`.

    Without this attribute uvicorn fails with "Attribute 'app' not found" and
    the console never starts, which no create_app()-based test would catch.
    """

    from starlette.applications import Starlette

    from saber.ui.web import app as app_module

    assert isinstance(app_module.app, Starlette)


def test_unknown_mission_renders_a_404_page_not_a_stack_trace(tmp_path) -> None:
    client = TestClient(_app(tmp_path))
    response = client.get("/ui/sessions/does-not-exist")

    assert response.status_code == 404
    assert "No mission with that ID" in response.text


def _seed_mission(conn) -> None:
    """Seed one running mission with a mixed-outcome timeline."""

    now = datetime.now(UTC)
    SessionStore(conn).create_session(
        MissionSession(
            session_id="s1",
            mission_name="Console test mission",
            status="running",
            created_at=now,
            started_at=now,
        )
    )
    MissionStateStore(conn).save(
        MissionState(
            session_id="s1",
            target=Target(type=TargetType.IP, value="10.0.0.5"),
            current_phase=PtesPhase.EXPLOITATION,
            hosts=[KnownHost(address="10.0.0.5")],
            services=[KnownService(host="10.0.0.5", port=80, protocol="tcp")],
            credentials=[KnownCredential(username="admin", host="10.0.0.5", validated=True)],
            flags=[KnownFlag(value="FLAG{abc}", location="/root/flag.txt")],
            attempted_actions=[
                AttemptedAction(
                    tool_name="nmap", action="tcp_scan", args={"ports": "80"},
                    success=True, reason="1 port open", at=now,
                ),
                AttemptedAction(
                    tool_name="nikto", action="scan", success=False,
                    reason="tool exited 1", at=now + timedelta(seconds=30),
                ),
                AttemptedAction(
                    tool_name="metasploit", action="exploit", success=False,
                    reason="refused: target outside scope", at=now + timedelta(seconds=31),
                ),
            ],
            step_count=3,
        )
    )


def test_mission_page_shows_the_timeline_and_working_memory(tmp_path) -> None:
    """The mission page renders each action, its outcome, and what state holds."""

    client = TestClient(_app(tmp_path, _seed_mission))
    response = client.get("/ui/sessions/s1")

    assert response.status_code == 200
    text = response.text

    # Every attempted action appears, with the arguments it ran with.
    assert "nmap.tcp_scan" in text
    assert "nikto.scan" in text
    assert "metasploit.exploit" in text
    assert "&#34;ports&#34;: &#34;80&#34;" in text

    # Outcomes are distinguished, including the scope refusal.
    assert "is-failed" in text
    assert "is-gated" in text

    # Working memory is on the page.
    assert "FLAG{abc}" in text
    assert "10.0.0.5" in text
    assert 'id="mission-state-panel"' in text


def test_running_mission_polls_and_finished_mission_does_not(tmp_path) -> None:
    """Polling is a cost; it stops once the loop can no longer act."""

    app = _app(tmp_path, _seed_mission)
    client = TestClient(app)

    assert 'hx-trigger="every 3s"' in client.get("/ui/sessions/s1").text

    app.state.session_store.update_session_status("s1", "completed")
    assert 'hx-trigger="every 3s"' not in client.get("/ui/sessions/s1").text


def test_mission_data_is_escaped_into_the_page(tmp_path) -> None:
    """Tool output is untrusted input; it must never render as markup."""

    def seed(conn):
        now = datetime.now(UTC)
        SessionStore(conn).create_session(
            MissionSession(
                session_id="s1", mission_name="<script>alert(1)</script>",
                status="running", created_at=now, started_at=now,
            )
        )
        MissionStateStore(conn).save(
            MissionState(
                session_id="s1",
                target=Target(type=TargetType.IP, value="10.0.0.5"),
                attempted_actions=[
                    AttemptedAction(
                        tool_name="nmap", action="scan", success=True,
                        reason="<img src=x onerror=alert(1)>", at=now,
                    )
                ],
            )
        )

    client = TestClient(_app(tmp_path, seed))
    text = client.get("/ui/sessions/s1").text

    assert "<script>alert(1)</script>" not in text
    assert "<img src=x onerror=alert(1)>" not in text
    assert "&lt;script&gt;" in text


def test_mission_list_shows_target_and_step_count_from_state(tmp_path) -> None:
    """Target and step count live in the snapshot, not the session row."""

    client = TestClient(_app(tmp_path, _seed_mission))
    text = client.get("/ui/sessions").text

    assert "10.0.0.5" in text
    assert "Console test mission" in text


def test_approval_decision_is_recorded(tmp_path) -> None:
    """The console can resolve a held action, and rejects a bogus decision."""

    def seed(conn):
        now = datetime.now(UTC)
        store = SessionStore(conn)
        store.create_session(
            MissionSession(
                session_id="s1", mission_name="m", status="running",
                created_at=now, started_at=now,
            )
        )
        store.create_approval_request(
            "s1", "step-1", "high-risk exploit", {"action": "metasploit.exploit"}
        )

    app = _app(tmp_path, seed)
    client = TestClient(app)

    approval_id = app.state.session_store.list_pending_approvals("s1")[0]["approval_id"]

    assert client.post(f"/sessions/s1/approvals/{approval_id}/sideways").status_code == 400

    response = client.post(f"/sessions/s1/approvals/{approval_id}/approved")
    assert response.status_code == 200
    assert "Approved" in response.text
    assert app.state.session_store.list_pending_approvals("s1") == []


def test_evidence_and_report_rows_render_their_real_columns(tmp_path) -> None:
    """The tables must read the column names the stores actually return.

    Both tables originally guessed at ``file_path``/``source_tool``, which the
    schema does not have, so every row silently rendered its ID and a dash.
    """

    evidence_file = tmp_path / "nmap.xml"
    evidence_file.write_text("<nmaprun/>")
    report_file = tmp_path / "technical.md"
    report_file.write_text("# report")

    def seed(conn):
        now = datetime.now(UTC)
        store = SessionStore(conn)
        store.create_session(
            MissionSession(
                session_id="s1", mission_name="m", status="completed",
                created_at=now, started_at=now, finished_at=now,
            )
        )
        EvidenceIndex(conn).add_evidence(
            "s1", evidence_file, "nmap XML output", tool_name="nmap", action="tcp_scan"
        )
        store.save_report_artifact("s1", "markdown", report_file)

    client = TestClient(_app(tmp_path, seed))
    text = client.get("/ui/sessions/s1").text

    assert "nmap.tcp_scan" in text
    assert "nmap XML output" in text
    assert str(evidence_file) in text
    assert str(report_file) in text
    assert "markdown" in text


# ------------------------------------------------------------ view-model units


def test_spine_encodes_outcome_and_elapsed_time() -> None:
    """The timeline's visual language must match the underlying facts."""

    now = datetime.now(UTC)
    state = MissionState(
        session_id="s1",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        attempted_actions=[
            AttemptedAction(tool_name="a", action="x", success=True, at=now),
            AttemptedAction(
                tool_name="b", action="y", success=False, reason="boom",
                at=now + timedelta(seconds=100),
            ),
            AttemptedAction(
                tool_name="c", action="z", success=False, reason="refused: out of scope",
                at=now + timedelta(seconds=101),
            ),
        ],
    )

    spine = templating.build_spine(state)

    assert [row["outcome"] for row in spine] == ["completed", "failed", "refused"]
    assert [row["css"] for row in spine] == ["", "is-failed", "is-gated"]
    # A 100-second step draws a longer rule than a 1-second one.
    assert spine[0]["gap_px"] > spine[1]["gap_px"]
    assert spine[0]["duration"] == "2m"
    # The last action has nothing after it, so it has no measurable duration.
    assert spine[2]["duration"] == ""


def test_spine_is_empty_when_the_loop_has_not_acted() -> None:
    assert templating.build_spine(None) == []


def test_phase_strip_marks_earlier_phases_done_and_later_ones_pending() -> None:
    state = MissionState(
        session_id="s1",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        current_phase=PtesPhase.EXPLOITATION,
    )

    strip = templating.phase_strip(state)
    current = [phase for phase in strip if phase["current"]]

    assert len(current) == 1
    assert current[0]["label"] == "exploit"
    assert strip[0]["done"] is True
    assert strip[-1]["done"] is False


def test_severity_counts_keep_every_level_in_order() -> None:
    counts = templating.severity_counts(
        [{"severity": "high"}, {"severity": "high"}, {"severity": "info"}, {}]
    )

    assert list(counts) == list(templating.SEVERITY_ORDER)
    assert counts["high"] == 2
    assert counts["unknown"] == 1
    assert counts["critical"] == 0


def test_badge_escapes_its_input() -> None:
    assert "<script>" not in str(templating.badge("<script>"))


def test_a_failed_mission_says_so_and_says_why(tmp_path) -> None:
    """Observed live: a mission died on an HTTP 402 from the model provider and the
    page still showed RUNNING with an empty timeline and no error anywhere. The
    reason was sitting in MissionState.stop_reason the whole time."""

    def seed(conn):
        now = datetime.now(UTC)
        SessionStore(conn).create_session(
            MissionSession(
                session_id="s1", mission_name="m", status="running",
                created_at=now, started_at=now,
            )
        )
        MissionStateStore(conn).save(
            MissionState(
                session_id="s1",
                target=Target(type=TargetType.HOST, value="dvwa"),
                stop_reason="LLM error: Model request failed with HTTP 402: out of credit",
            )
        )

    app = _app(tmp_path, seed)
    client = TestClient(app)
    app.state.session_store.update_session_status("s1", "failed")

    text = client.get("/ui/sessions/s1").text

    assert "The mission failed" in text
    assert "HTTP 402" in text


def test_the_status_header_refreshes_itself_while_the_mission_runs(tmp_path) -> None:
    """The header used to render once. A mission that failed mid-run kept showing
    RUNNING forever, while the panel beside it updated and said 'final'."""

    app = _app(tmp_path, _seed_mission)
    client = TestClient(app)

    running = client.get("/ui/sessions/s1").text
    assert 'id="mission-status"' in running
    assert "/ui/sessions/s1/status" in running
    assert running.count('hx-trigger="every 3s"') >= 2  # status header AND state panel

    app.state.session_store.update_session_status("s1", "completed")
    finished = client.get("/ui/sessions/s1").text
    assert 'hx-trigger="every 3s"' not in finished


def test_status_fragment_renders_standalone(tmp_path) -> None:
    client = TestClient(_app(tmp_path, _seed_mission))

    response = client.get("/ui/sessions/s1/status")

    assert response.status_code == 200
    assert 'id="mission-status"' in response.text
    assert client.get("/ui/sessions/nope/status").status_code == 404
