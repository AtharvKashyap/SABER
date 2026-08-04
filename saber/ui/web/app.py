"""SABER FastAPI web application."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.storage.mission_state_store import MissionStateStore
from saber.storage.session_store import SessionStore
from saber.ui.cli.run_command import PROFILE_AGENTS
from saber.ui.web import templating
from saber.ui.web.routers import findings, mission_state, reports, sessions

PUBLIC_PATHS = {
    "/",
    "/ui",
    "/ui/sessions",
    "/ui/findings",
    "/ui/reports",
    "/ui/partials/running",
    "/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}


def create_app(
    db_path: str | Path = "runs/saber.db",
    reports_dir: str | Path = "runs/reports",
    evidence_dir: str | Path = "runs/evidence",
    allow_origins: list[str] | None = None,
    api_key: str | None = None,
    require_auth: bool | None = None,
) -> FastAPI:
    """Create and configure SABER web app."""

    resolved_api_key = api_key or os.environ.get("SABER_API_KEY")
    auth_required = require_auth if require_auth is not None else bool(resolved_api_key)

    app = FastAPI(
        title="SABER",
        description="Scoped Automated Breach, Exploitation & Reporting web API.",
        version="0.1.0",
    )

    origins = allow_origins if allow_origins is not None else [
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-SABER-API-Key"],
    )

    connection = StorageConnection(db_path)
    connection.initialize()

    reports_root = Path(reports_dir).resolve()
    reports_root.mkdir(parents=True, exist_ok=True)
    evidence_root = Path(evidence_dir).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)

    app.state.db_path = str(db_path)
    app.state.reports_dir = str(reports_root)
    app.state.evidence_dir = str(evidence_root)
    app.state.auth_required = auth_required
    app.state.api_key = resolved_api_key
    app.state.storage_connection = connection
    app.state.session_store = SessionStore(connection)
    app.state.finding_store = FindingStore(connection)
    app.state.evidence_index = EvidenceIndex(connection)
    app.state.graph_store = GraphStore(connection)
    app.state.mission_state_store = MissionStateStore(connection)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: Any) -> Any:
        """Apply API-key auth and security headers."""

        path = request.url.path
        public = (
            path in PUBLIC_PATHS
            or path.startswith("/ui/sessions/")
            or path.startswith("/static/")
        )

        if app.state.auth_required and not public:
            supplied = request.headers.get("X-SABER-API-Key")
            authorization = request.headers.get("Authorization", "")

            bearer = ""
            if authorization.lower().startswith("bearer "):
                bearer = authorization.split(" ", 1)[1].strip()

            if supplied != app.state.api_key and bearer != app.state.api_key:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            # Every asset the console needs is served from this origin, so the
            # policy no longer allows a CDN. The page works air-gapped.
            #
            # script-src stays strict. style-src allows inline because the console
            # sizes elements from live data (severity bars, timeline rule lengths)
            # via style attributes; Jinja autoescaping is what keeps that safe.
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

    app.include_router(sessions.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(mission_state.router)

    app.mount(
        "/static",
        StaticFiles(directory=str(templating.STATIC_DIR)),
        name="static",
    )
    templates = templating.build_environment()
    app.state.templates = templates

    def _render(name: str, request: Request, **context: Any) -> str:
        """Render a template with the navigation counts every page shows."""

        return templates.get_template(name).render(nav=_nav_counts(request), **context)

    def _nav_counts(request: Request) -> dict[str, int]:
        """Return the rail's badge counts."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store

        sessions_rows = session_store.list_sessions(limit=1000)
        findings_total = 0
        reports_total = 0
        for row in sessions_rows:
            findings_total += len(finding_store.list_findings(row["session_id"]))
            reports_total += len(session_store.list_report_artifacts(row["session_id"]))

        return {
            "sessions": len(sessions_rows),
            "findings": findings_total,
            "reports": reports_total,
        }

    def _session_rows(request: Request, limit: int = 200) -> list[dict[str, Any]]:
        """Return session rows enriched with target and step count from state."""

        session_store: SessionStore = request.app.state.session_store
        state_store: MissionStateStore = request.app.state.mission_state_store

        digests = state_store.summaries()
        rows: list[dict[str, Any]] = []
        for row in session_store.list_sessions(limit=limit):
            digest = digests.get(row["session_id"], {})
            rows.append(
                {
                    **row,
                    "target": digest.get("target"),
                    "step_count": digest.get("step_count", 0),
                    "started_at": row.get("created_at"),
                }
            )
        return rows

    def _all_findings(request: Request) -> list[dict[str, Any]]:
        """Return every finding across every session."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store

        rows: list[dict[str, Any]] = []
        for session in session_store.list_sessions(limit=1000):
            rows.extend(finding_store.list_findings(session["session_id"]))
        return rows

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request) -> HTMLResponse:
        """Redirectless alias for the console home."""

        return dashboard(request)

    @app.get("/ui", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        """Mission launch page."""

        rows = _session_rows(request)
        running = [row for row in rows if str(row.get("status")) in templating.LIVE_STATUSES]

        return HTMLResponse(
            _render(
                "dashboard.html.j2",
                request,
                title="Launch a mission",
                active="dashboard",
                profiles=sorted(PROFILE_AGENTS),
                sessions=rows[:8],
                running=running,
                severity_counts=templating.severity_counts(_all_findings(request)),
            )
        )

    @app.get("/ui/partials/running", response_class=HTMLResponse)
    def ui_running_partial(request: Request) -> HTMLResponse:
        """In-flight mission strip, polled by the launch page."""

        rows = _session_rows(request)
        running = [row for row in rows if str(row.get("status")) in templating.LIVE_STATUSES]
        return HTMLResponse(
            templates.get_template("partials/running.html.j2").render(running=running)
        )

    @app.get("/ui/sessions", response_class=HTMLResponse)
    def ui_sessions(request: Request) -> HTMLResponse:
        """Mission list page."""

        rows = _session_rows(request)
        status_counts = Counter(str(row.get("status") or "unknown") for row in rows)

        stats = [
            ("Missions", len(rows)),
            ("Running", sum(status_counts[s] for s in templating.LIVE_STATUSES)),
            ("Completed", status_counts.get("completed", 0)),
            ("Steps taken", sum(int(row.get("step_count") or 0) for row in rows)),
        ]

        return HTMLResponse(
            _render(
                "sessions.html.j2",
                request,
                title="Missions",
                active="sessions",
                sessions=rows,
                stats=stats,
            )
        )

    def _mission_context(request: Request, session_id: str) -> dict[str, Any] | None:
        """Build the mission page view model, or None when the session is unknown."""

        session_store: SessionStore = request.app.state.session_store
        state_store: MissionStateStore = request.app.state.mission_state_store

        session = session_store.get_session(session_id)
        if not session:
            return None

        state = state_store.load(session_id)
        status = str(session.get("status") or "unknown")

        return {
            "session": {**session, "target": state.target.value if state else None},
            "state": state,
            "live": status in templating.LIVE_STATUSES,
            "phases": templating.phase_strip(state),
            "ledger": templating.state_ledger(state),
            "spine": templating.build_spine(state),
            "stop_reason": state.stop_reason if state else None,
        }

    @app.get("/ui/sessions/{session_id}", response_class=HTMLResponse)
    def ui_session_detail(request: Request, session_id: str) -> HTMLResponse:
        """Mission detail page."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store
        evidence_index: EvidenceIndex = request.app.state.evidence_index

        context = _mission_context(request, session_id)
        if context is None:
            return HTMLResponse(
                _render(
                    "not_found.html.j2",
                    request,
                    title="Mission not found",
                    active="sessions",
                    session_id=session_id,
                ),
                status_code=404,
            )

        return HTMLResponse(
            _render(
                "mission.html.j2",
                request,
                title=context["session"].get("mission_name") or session_id,
                active="sessions",
                findings=finding_store.list_findings(session_id),
                evidence=evidence_index.list_evidence(session_id),
                reports=session_store.list_report_artifacts(session_id),
                approvals=session_store.list_pending_approvals(session_id),
                show_mission=False,
                **context,
            )
        )

    @app.get("/ui/sessions/{session_id}/status", response_class=HTMLResponse)
    def ui_status_fragment(request: Request, session_id: str) -> HTMLResponse:
        """Mission status and outcome, polled by the mission page."""

        context = _mission_context(request, session_id)
        if context is None:
            return HTMLResponse("", status_code=404)

        return HTMLResponse(
            templates.get_template("partials/mission_status.html.j2").render(**context)
        )

    @app.get("/ui/sessions/{session_id}/state-panel", response_class=HTMLResponse)
    def ui_state_panel(request: Request, session_id: str) -> HTMLResponse:
        """Live working-memory panel, polled by the mission page."""

        context = _mission_context(request, session_id)
        if context is None:
            return HTMLResponse("", status_code=404)

        return HTMLResponse(
            templates.get_template("partials/state_panel.html.j2").render(**context)
        )

    @app.get("/ui/findings", response_class=HTMLResponse)
    def ui_findings(request: Request) -> HTMLResponse:
        """Findings across every mission."""

        rows = _all_findings(request)
        return HTMLResponse(
            _render(
                "findings.html.j2",
                request,
                title="Findings",
                active="findings",
                findings=rows,
                severity_counts=templating.severity_counts(rows),
                show_mission=True,
            )
        )

    @app.get("/ui/reports", response_class=HTMLResponse)
    def ui_reports(request: Request) -> HTMLResponse:
        """Generated report artifacts."""

        session_store: SessionStore = request.app.state.session_store

        rows: list[dict[str, Any]] = []
        for session in session_store.list_sessions(limit=1000):
            rows.extend(session_store.list_report_artifacts(session["session_id"]))

        return HTMLResponse(
            _render(
                "reports.html.j2",
                request,
                title="Reports",
                active="reports",
                reports=rows,
                show_mission=True,
            )
        )

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Return health status."""

        storage_ok = True
        storage_error = None

        try:
            app.state.storage_connection.query_one("SELECT 1 AS ok")
        except Exception as exc:  # pragma: no cover
            storage_ok = False
            storage_error = f"{type(exc).__name__}: {exc}"

        return {
            "status": "ok" if storage_ok else "degraded",
            "storage": "ok" if storage_ok else "error",
            "db_path": app.state.db_path,
            "reports_dir": app.state.reports_dir,
            "auth_required": app.state.auth_required,
            "error": storage_error,
        }

    @app.on_event("shutdown")
    def shutdown() -> None:
        """Close storage connection on shutdown."""

        app.state.storage_connection.close()

    return app


# Module-level ASGI application. `./run_saber` / `scripts/launch_saber.py` start
# the console with `uvicorn saber.ui.web.app:app`, so this attribute is part of
# this module's contract, not an accident. tests/unit/test_web_console.py pins it.
app = create_app()
