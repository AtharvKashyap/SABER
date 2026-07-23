"""SABER FastAPI web application."""

from __future__ import annotations

import html
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.storage.mission_state_store import MissionStateStore
from saber.storage.session_store import SessionStore
from saber.ui.web.routers import findings, mission_state, reports, sessions


PUBLIC_PATHS = {
    "/",
    "/ui",
    "/ui/sessions",
    "/ui/findings",
    "/ui/reports",
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
        public = path in PUBLIC_PATHS or path.startswith("/ui/sessions/")

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
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

    app.include_router(sessions.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(mission_state.router)

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request) -> HTMLResponse:
        """Dashboard page."""

        return dashboard(request)

    @app.get("/ui", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        """SABER dashboard page."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store
        evidence_index: EvidenceIndex = request.app.state.evidence_index

        session_rows = session_store.list_sessions(limit=1000)
        all_findings: list[dict[str, Any]] = []
        all_evidence: list[dict[str, Any]] = []
        pending_approvals: list[dict[str, Any]] = []

        for session in session_rows:
            session_id = session["session_id"]
            all_findings.extend(finding_store.list_findings(session_id))
            all_evidence.extend(evidence_index.list_evidence(session_id))
            pending_approvals.extend(session_store.list_pending_approvals(session_id))

        status_counts = Counter(str(session.get("status") or "unknown") for session in session_rows)
        severity_counts = Counter(str(finding.get("severity") or "unknown") for finding in all_findings)
        source_counts = Counter(str(finding.get("source_tool") or "unknown") for finding in all_findings)

        body = f"""
        <section class="hero">
          <div>
            <p class="eyebrow">Scoped Automated Breach, Exploitation & Reporting</p>
            <h1>SABER Mission Dashboard</h1>
            <p class="muted">Track missions, agents, approvals, findings, evidence, and reports from one operator view.</p>
          </div>
          <div class="hero-actions">
            <a class="button" href="/docs">API Docs</a>
            <a class="button secondary" href="/health">Health</a>
          </div>
        </section>

        {_mission_start_panel()}

        <section class="cards">
          {_card("Sessions", len(session_rows), "Stored mission sessions")}
          {_card("Findings", len(all_findings), "Normalized security findings")}
          {_card("Evidence", len(all_evidence), "Indexed evidence files")}
          {_card("Pending Approvals", len(pending_approvals), "Actions waiting for operator review")}
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Mission Status</h2>
            {_bar_chart(status_counts, "status")}
          </div>
          <div class="panel">
            <h2>Findings by Severity</h2>
            {_severity_chart(severity_counts)}
          </div>
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Findings by Tool</h2>
            {_bar_chart(source_counts, "tool")}
          </div>
          <div class="panel">
            <h2>Pending Approvals</h2>
            {_approval_list(pending_approvals)}
          </div>
        </section>

        <section class="panel">
          <div class="section-title">
            <h2>Recent Sessions</h2>
            <a href="/ui/sessions">View all</a>
          </div>
          {_sessions_table(session_rows[:10])}
        </section>
        """

        return HTMLResponse(_layout("SABER Dashboard", body))

    @app.get("/ui/sessions", response_class=HTMLResponse)
    def ui_sessions(request: Request) -> HTMLResponse:
        """Session list page."""

        session_store: SessionStore = request.app.state.session_store
        rows = session_store.list_sessions(limit=1000)

        body = f"""
        <section class="section-title">
          <div>
            <h1>Sessions</h1>
            <p class="muted">All stored SABER missions.</p>
          </div>
          <a class="button secondary" href="/sessions">JSON API</a>
        </section>
        <section class="panel">
          {_sessions_table(rows)}
        </section>
        """

        return HTMLResponse(_layout("Sessions", body))

    @app.get("/ui/sessions/{session_id}", response_class=HTMLResponse)
    def ui_session_detail(request: Request, session_id: str) -> HTMLResponse:
        """Session detail page."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store
        evidence_index: EvidenceIndex = request.app.state.evidence_index
        graph_store: GraphStore = request.app.state.graph_store

        session = session_store.get_session(session_id)
        if not session:
            return HTMLResponse(_layout("Not Found", f"<h1>Session not found</h1><p>{_e(session_id)}</p>"), status_code=404)

        steps = session_store.list_steps(session_id)
        records = session_store.list_step_records(session_id)
        approvals = session_store.list_pending_approvals(session_id)
        reports_list = session_store.list_report_artifacts(session_id)
        findings_list = finding_store.list_findings(session_id)
        observations = finding_store.list_observations(session_id)
        evidence = evidence_index.list_evidence(session_id)
        nodes = graph_store.list_nodes(session_id)
        edges = graph_store.list_edges(session_id)
        attack_paths = graph_store.list_attack_paths(session_id)

        severity_counts = Counter(str(finding.get("severity") or "unknown") for finding in findings_list)
        step_counts = Counter(str(step.get("status") or "unknown") for step in steps)

        body = f"""
        <section class="hero">
          <div>
            <p class="eyebrow">Session</p>
            <h1>{_e(session.get("mission_name"))}</h1>
            <p class="muted"><code>{_e(session_id)}</code> · {_badge(session.get("status"))}</p>
          </div>
          <div class="hero-actions">
            <a class="button" href="/sessions/{_e(session_id)}">JSON</a>
            <a class="button secondary" href="/ui/sessions">Back</a>
          </div>
        </section>

        <section class="cards">
          {_card("Steps", len(steps), "Agent execution steps")}
          {_card("Findings", len(findings_list), "Security findings")}
          {_card("Evidence", len(evidence), "Evidence files")}
          {_card("Approvals", len(approvals), "Pending approvals")}
        </section>

        {_mission_state_panel(session_id)}

        <section class="grid two">
          <div class="panel">
            <h2>Step Status</h2>
            {_bar_chart(step_counts, "status")}
          </div>
          <div class="panel">
            <h2>Finding Severity</h2>
            {_severity_chart(severity_counts)}
          </div>
        </section>

        <section class="panel">
          <h2>Agent Timeline</h2>
          {_steps_timeline(steps, records)}
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Pending Approvals</h2>
            {_approval_list(approvals)}
          </div>
          <div class="panel">
            <h2>AD / Lateral Movement Graph Summary</h2>
            <div class="mini-grid">
              {_mini_stat("Nodes", len(nodes))}
              {_mini_stat("Edges", len(edges))}
              {_mini_stat("Attack Paths", len(attack_paths))}
            </div>
          </div>
        </section>

        <section class="panel">
          <h2>Findings</h2>
          {_findings_table(findings_list)}
        </section>

        <section class="panel">
          <h2>Observations</h2>
          {_observations_table(observations)}
        </section>

        <section class="panel">
          <h2>Evidence</h2>
          {_evidence_table(evidence)}
        </section>

        <section class="panel">
          <h2>Reports</h2>
          {_reports_table(reports_list)}
        </section>
        """

        return HTMLResponse(_layout(f"Session {session_id}", body))

    @app.get("/ui/findings", response_class=HTMLResponse)
    def ui_findings(request: Request) -> HTMLResponse:
        """Findings page."""

        session_store: SessionStore = request.app.state.session_store
        finding_store: FindingStore = request.app.state.finding_store

        rows: list[dict[str, Any]] = []
        for session in session_store.list_sessions(limit=1000):
            rows.extend(finding_store.list_findings(session["session_id"]))

        body = f"""
        <section class="section-title">
          <div>
            <h1>Findings</h1>
            <p class="muted">Normalized findings across all sessions.</p>
          </div>
          <a class="button secondary" href="/findings">JSON API</a>
        </section>
        <section class="panel">
          {_findings_table(rows)}
        </section>
        """

        return HTMLResponse(_layout("Findings", body))

    @app.get("/ui/reports", response_class=HTMLResponse)
    def ui_reports(request: Request) -> HTMLResponse:
        """Reports page."""

        session_store: SessionStore = request.app.state.session_store

        rows: list[dict[str, Any]] = []
        for session in session_store.list_sessions(limit=1000):
            rows.extend(session_store.list_report_artifacts(session["session_id"]))

        body = f"""
        <section class="section-title">
          <div>
            <h1>Reports</h1>
            <p class="muted">Generated report artifacts.</p>
          </div>
          <a class="button secondary" href="/reports">JSON API</a>
        </section>
        <section class="panel">
          {_reports_table(rows)}
        </section>
        """

        return HTMLResponse(_layout("Reports", body))

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


def _layout(title: str, body: str) -> str:
    """Render full HTML page."""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_e(title)} · SABER</title>
  <style>
    :root {{
      --bg: #0b1020;
      --panel: #121a2f;
      --panel2: #18213a;
      --text: #eef3ff;
      --muted: #9fb0d0;
      --border: #2a375a;
      --accent: #7aa2ff;
      --good: #52d273;
      --warn: #ffd166;
      --bad: #ff6b6b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #17213d, var(--bg) 42%);
      color: var(--text);
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    code {{ background: #0b1020; padding: 2px 6px; border-radius: 6px; border: 1px solid var(--border); }}
    .nav {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 28px;
      border-bottom: 1px solid var(--border);
      background: rgba(11, 16, 32, 0.82);
      position: sticky;
      top: 0;
      backdrop-filter: blur(10px);
      z-index: 10;
    }}
    .brand {{ font-weight: 800; letter-spacing: 0.08em; }}
    .nav-links {{ display: flex; gap: 18px; align-items: center; }}
    .container {{ max-width: 1220px; margin: 0 auto; padding: 30px 24px 60px; }}
    .hero, .section-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 24px;
    }}
    h1 {{ font-size: 36px; line-height: 1.1; margin: 6px 0 8px; }}
    h2 {{ margin: 0 0 16px; font-size: 20px; }}
    .eyebrow {{ color: var(--accent); text-transform: uppercase; font-size: 12px; letter-spacing: 0.12em; font-weight: 700; }}
    .muted {{ color: var(--muted); }}
    .hero-actions {{ display: flex; gap: 10px; }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 14px;
      border-radius: 10px;
      background: var(--accent);
      color: #071022;
      font-weight: 700;
      border: 1px solid transparent;
    }}
    .button.secondary {{
      background: transparent;
      color: var(--text);
      border-color: var(--border);
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
      margin-bottom: 18px;
    }}
    .card, .panel {{
      background: linear-gradient(180deg, var(--panel), #0f172b);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.22);
    }}
    .card {{ padding: 18px; }}
    .card .value {{ font-size: 34px; font-weight: 850; margin: 8px 0; }}
    .panel {{ padding: 18px; margin-bottom: 18px; overflow: hidden; }}
    .grid.two {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }}
    .mini-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
    .mini-stat {{ background: var(--panel2); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
    .mini-stat strong {{ display: block; font-size: 26px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .badge {{
      display: inline-flex;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      border: 1px solid var(--border);
      background: var(--panel2);
    }}
    .badge.completed, .badge.running {{ color: var(--good); }}
    .badge.high, .badge.critical, .badge.failed {{ color: var(--bad); }}
    .badge.needs_approval, .badge.pending, .badge.medium {{ color: var(--warn); }}
    .bar-row {{ display: grid; grid-template-columns: 120px 1fr 42px; gap: 12px; align-items: center; margin: 10px 0; }}
    .bar-track {{ height: 12px; border-radius: 999px; background: #0b1020; border: 1px solid var(--border); overflow: hidden; }}
    .bar-fill {{ height: 100%; background: var(--accent); border-radius: 999px; }}
    .timeline {{ display: grid; gap: 10px; }}
    .timeline-item {{ display: grid; grid-template-columns: 150px 1fr; gap: 16px; padding: 12px; background: var(--panel2); border-radius: 12px; border: 1px solid var(--border); }}
    pre {{ white-space: pre-wrap; overflow: auto; background: #080d1a; border: 1px solid var(--border); padding: 12px; border-radius: 12px; color: var(--muted); }}
    @media (max-width: 900px) {{
      .cards, .grid.two {{ grid-template-columns: 1fr; }}
      .hero, .section-title {{ align-items: flex-start; flex-direction: column; }}
      .nav {{ align-items: flex-start; flex-direction: column; gap: 12px; }}
    }}
  </style>
</head>
<body>
  <nav class="nav">
    <a class="brand" href="/ui">SABER</a>
    <div class="nav-links">
      <a href="/ui">Dashboard</a>
      <a href="/ui/sessions">Sessions</a>
      <a href="/ui/findings">Findings</a>
      <a href="/ui/reports">Reports</a>
      <a href="/docs">API Docs</a>
    </div>
  </nav>
  <main class="container">{body}</main>
</body>
</html>"""



def _mission_start_panel() -> str:
    """Render mission start form."""

    return """
    <section class="panel">
      <div class="section-title">
        <div>
          <h2>Start Mission</h2>
          <p class="muted">Launch a scoped SABER mission from the browser.</p>
        </div>
      </div>

      <form id="mission-start-form" class="mission-form" onsubmit="return startMission(event)">
        <label>Target
          <input id="mission-target" name="target" value="127.0.0.1" required />
        </label>

        <label>Profile
          <select id="mission-profile" name="profile">
            <option value="recon">recon</option>
            <option value="web">web</option>
            <option value="network">network</option>
            <option value="full">full</option>
          </select>
        </label>

        <label>Mode
          <select id="mission-agent-mode" name="agent_mode">
            <option value="deterministic">deterministic</option>
            <option value="llm">llm</option>
          </select>
        </label>

        <label>Strategy
          <select id="mission-strategy" name="strategy">
            <option value="auto">auto</option>
            <option value="network">network</option>
            <option value="web">web</option>
            <option value="ctf">ctf</option>
          </select>
        </label>

        <label>Max Steps
          <input id="mission-max-steps" name="max_steps" type="number" min="1" max="200" value="20" />
        </label>

        <label class="checkbox-row">
          <input id="mission-require-approval" name="require_approval" type="checkbox" checked />
          Require approval for risky actions
        </label>

        <label class="checkbox-row">
          <input id="mission-dry-run" name="dry_run" type="checkbox" />
          Dry run
        </label>

        <label class="checkbox-row">
          <input id="mission-lab" name="lab" type="checkbox" />
          Lab target (owned)
        </label>

        <label class="wide">Objective
          <textarea id="mission-objective" name="objective" rows="3">Run a safe scoped assessment and produce reports.</textarea>
        </label>

        <button class="button" type="submit">Start Mission</button>
      </form>

      <div id="mission-start-result" class="muted"></div>

      <script>
      async function startMission(event) {
        event.preventDefault();

        const result = document.getElementById("mission-start-result");
        result.innerHTML = "Starting mission...";

        const payload = {
          target: document.getElementById("mission-target").value,
          profile: document.getElementById("mission-profile").value,
          agent_mode: document.getElementById("mission-agent-mode").value,
          strategy: document.getElementById("mission-strategy").value,
          max_steps: parseInt(document.getElementById("mission-max-steps").value || "20", 10),
          require_approval: document.getElementById("mission-require-approval").checked,
          dry_run: document.getElementById("mission-dry-run").checked,
          lab: document.getElementById("mission-lab").checked,
          objective: document.getElementById("mission-objective").value
        };

        const response = await fetch("/sessions/run", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
          result.innerHTML = "Error: " + (data.detail || JSON.stringify(data));
          return false;
        }

        result.innerHTML = `
          Mission started: <code>${data.session_id}</code><br>
          <a class="button secondary" href="${data.detail_url}">Open mission progress</a>
          <span id="mission-poll-status">Waiting for session...</span>
        `;

        pollMissionFromDashboard(data.session_id, data.detail_url);
        return false;
      }

      async function pollMissionFromDashboard(sessionId, detailUrl) {
        const status = document.getElementById("mission-poll-status");

        for (let i = 0; i < 120; i++) {
          await new Promise(resolve => setTimeout(resolve, 1000));

          const response = await fetch(`/sessions/${sessionId}`);
          if (!response.ok) {
            status.innerHTML = " Waiting for mission record...";
            continue;
          }

          const data = await response.json();
          const sessionStatus = data.session.status;
          status.innerHTML = ` Status: <strong>${sessionStatus}</strong>`;

          if (["completed", "failed", "paused_for_approval", "stopped"].includes(sessionStatus)) {
            status.innerHTML += ` · <a href="${detailUrl}">View results</a>`;
            break;
          }
        }
      }
      </script>
    </section>
    """

def _mission_state_panel(session_id: str) -> str:
    """Render the live MissionState panel for the mission detail page.

    The panel polls ``/api/sessions/{session_id}/state`` on the same 1s interval
    as the dashboard mission-progress poll and re-renders hosts, services,
    vulns, hypotheses, and the attempted-action timeline as they accumulate.
    """

    session_json = json.dumps(session_id)

    markup = """
    <section class="panel" id="mission-state-panel">
      <div class="section-title">
        <div>
          <h2>Mission State</h2>
          <p class="muted">Live working memory the agent loop reasons over.</p>
        </div>
        <span id="mission-state-status" class="muted">Loading live state...</span>
      </div>

      <div class="mini-grid" id="mission-state-counts"></div>

      <div class="grid two">
        <div>
          <h2>Hosts</h2>
          <div id="mission-state-hosts"><p class="muted">None yet.</p></div>
        </div>
        <div>
          <h2>Services</h2>
          <div id="mission-state-services"><p class="muted">None yet.</p></div>
        </div>
      </div>

      <div class="grid two">
        <div>
          <h2>Vulnerabilities</h2>
          <div id="mission-state-vulns"><p class="muted">None yet.</p></div>
        </div>
        <div>
          <h2>Hypotheses</h2>
          <div id="mission-state-hypotheses"><p class="muted">None yet.</p></div>
        </div>
      </div>

      <h2>Action Timeline</h2>
      <div id="mission-state-timeline"><p class="muted">None yet.</p></div>
    </section>

    <script>
    (function () {
      const sessionId = __SESSION_ID__;
      const statusEl = document.getElementById("mission-state-status");
      const countsEl = document.getElementById("mission-state-counts");
      const hostsEl = document.getElementById("mission-state-hosts");
      const servicesEl = document.getElementById("mission-state-services");
      const vulnsEl = document.getElementById("mission-state-vulns");
      const hypothesesEl = document.getElementById("mission-state-hypotheses");
      const timelineEl = document.getElementById("mission-state-timeline");

      function esc(value) {
        return String(value === null || value === undefined ? "" : value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }

      function miniStat(label, value) {
        return '<div class="mini-stat"><strong>' + esc(value) +
          '</strong><span class="muted">' + esc(label) + '</span></div>';
      }

      function renderTable(headers, rows) {
        if (!rows.length) {
          return '<p class="muted">None yet.</p>';
        }
        const head = headers.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join("");
        const body = rows.map(function (cells) {
          const tds = cells.map(function (c) { return '<td>' + esc(c) + '</td>'; }).join("");
          return '<tr>' + tds + '</tr>';
        }).join("");
        return '<table><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>';
      }

      function render(data) {
        const counts = (data.summary && data.summary.counts) || {};
        countsEl.innerHTML =
          miniStat("Hosts", counts.hosts || 0) +
          miniStat("Services", counts.services || 0) +
          miniStat("Technologies", counts.technologies || 0) +
          miniStat("Vulns", counts.vulns || 0) +
          miniStat("Hypotheses", counts.hypotheses || 0) +
          miniStat("Actions", counts.attempted_actions || 0);

        hostsEl.innerHTML = renderTable(
          ["Address", "OS", "Hostnames"],
          (data.hosts || []).map(function (h) {
            return [h.address, h.os || "", (h.hostnames || []).join(", ")];
          })
        );

        servicesEl.innerHTML = renderTable(
          ["Host", "Port", "Proto", "Service", "Product", "Version"],
          (data.services || []).map(function (s) {
            return [s.host, s.port, s.protocol, s.service || "", s.product || "", s.version || ""];
          })
        );

        vulnsEl.innerHTML = renderTable(
          ["Severity", "Title", "Host", "Port", "Confirmed"],
          (data.vulns || []).map(function (v) {
            const port = v.port == null ? "" : v.port;
            const confirmed = v.confirmed ? "yes" : "no";
            return [v.severity, v.title, v.host || "", port, confirmed];
          })
        );

        hypothesesEl.innerHTML = renderTable(
          ["Statement", "Confidence", "Status"],
          (data.hypotheses || []).map(function (h) {
            return [h.statement, h.confidence, h.status];
          })
        );

        timelineEl.innerHTML = renderTable(
          ["Tool", "Action", "Result", "Reason"],
          (data.timeline || []).map(function (a) {
            return [a.tool_name, a.action, a.success ? "success" : "failed", a.reason || ""];
          })
        );
      }

      let stopped = false;

      async function poll(iteration) {
        if (stopped || iteration > 600) {
          return;
        }
        try {
          const response = await fetch("/api/sessions/" + encodeURIComponent(sessionId) + "/state");
          if (response.status === 404) {
            statusEl.textContent = "No mission state recorded yet.";
          } else if (response.ok) {
            const data = await response.json();
            render(data);
            const summary = data.summary || {};
            const updated = summary.updated_at ? " - updated " + esc(summary.updated_at) : "";
            if (summary.objective_met || summary.stop_reason) {
              statusEl.innerHTML = "Final" + updated;
              stopped = true;
              return;
            }
            statusEl.innerHTML = "Live" + updated;
          } else {
            statusEl.textContent = "State unavailable (" + response.status + ")";
          }
        } catch (err) {
          statusEl.textContent = "State poll error";
        }
        setTimeout(function () { poll(iteration + 1); }, 1000);
      }

      poll(0);
    })();
    </script>
    """

    return markup.replace("__SESSION_ID__", session_json)


def _card(title: str, value: int, caption: str) -> str:
    return f"""
    <div class="card">
      <div class="muted">{_e(title)}</div>
      <div class="value">{value}</div>
      <div class="muted">{_e(caption)}</div>
    </div>
    """


def _mini_stat(title: str, value: int) -> str:
    return f'<div class="mini-stat"><strong>{value}</strong><span class="muted">{_e(title)}</span></div>'


def _sessions_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No sessions yet.</p>'

    body = "".join(
        f"""
        <tr>
          <td><a href="/ui/sessions/{_e(row.get("session_id"))}">{_e(row.get("session_id"))}</a></td>
          <td>{_e(row.get("mission_name"))}</td>
          <td>{_badge(row.get("status"))}</td>
          <td>{_e(row.get("created_at"))}</td>
          <td>{_e(row.get("updated_at"))}</td>
        </tr>
        """
        for row in rows
    )

    return f"""
    <table>
      <thead><tr><th>Session</th><th>Mission</th><th>Status</th><th>Created</th><th>Updated</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _findings_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No findings yet.</p>'

    body = "".join(
        f"""
        <tr>
          <td>{_badge(row.get("severity"))}</td>
          <td>{_e(row.get("title"))}</td>
          <td>{_badge(row.get("status"))}</td>
          <td>{_e(row.get("source_tool"))}</td>
          <td>{_e(row.get("session_id"))}</td>
        </tr>
        """
        for row in rows
    )

    return f"""
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Tool</th><th>Session</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _observations_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No observations yet.</p>'

    body = "".join(
        f"""
        <tr>
          <td>{_e(row.get("kind"))}</td>
          <td>{_e(row.get("summary"))}</td>
          <td>{_e(row.get("source_tool"))}</td>
        </tr>
        """
        for row in rows
    )

    return f"""
    <table>
      <thead><tr><th>Kind</th><th>Summary</th><th>Tool</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _evidence_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No evidence yet.</p>'

    body = "".join(
        f"""
        <tr>
          <td>{_e(row.get("title"))}</td>
          <td>{_e(row.get("tool_name"))}</td>
          <td><code>{_e(row.get("path"))}</code></td>
          <td>{_e(row.get("sha256"))[:12]}...</td>
        </tr>
        """
        for row in rows
    )

    return f"""
    <table>
      <thead><tr><th>Title</th><th>Tool</th><th>Path</th><th>SHA-256</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _reports_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No reports generated yet.</p>'

    body = "".join(
        f"""
        <tr>
          <td>{_e(row.get("report_type"))}</td>
          <td><code>{_e(row.get("path"))}</code></td>
          <td>{_e(row.get("created_at"))}</td>
          <td><a href="/reports/{_e(row.get("report_id"))}/download">Download</a></td>
        </tr>
        """
        for row in rows
    )

    return f"""
    <table>
      <thead><tr><th>Type</th><th>Path</th><th>Created</th><th>Download</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
    """


def _approval_list(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="muted">No pending approvals.</p>'

    items = "".join(
        f"""
        <div class="timeline-item">
          <div>{_badge(row.get("status"))}</div>
          <div>
            <strong>{_e(row.get("reason"))}</strong>
            <p class="muted">Session {_e(row.get("session_id"))} · Step {_e(row.get("step_id"))}</p>
            {_json_block(row.get("requested_action"))}
          </div>
        </div>
        """
        for row in rows
    )
    return f'<div class="timeline">{items}</div>'


def _steps_timeline(steps: list[dict[str, Any]], records: list[dict[str, Any]]) -> str:
    if not steps:
        return '<p class="muted">No steps yet.</p>'

    records_by_step: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        records_by_step.setdefault(str(record.get("step_id")), []).append(record)

    items = []
    for step in steps:
        step_id = str(step.get("step_id"))
        related_records = records_by_step.get(step_id, [])
        records_html = "".join(_json_block(record.get("record")) for record in related_records)

        items.append(
            f"""
            <div class="timeline-item">
              <div>
                {_badge(step.get("status"))}
                <p class="muted">{_e(step.get("phase"))}</p>
              </div>
              <div>
                <strong>{_e(step.get("agent_name"))}</strong>
                <p>{_e(step.get("objective"))}</p>
                <p class="muted">Step <code>{_e(step_id)}</code></p>
                {_json_block(step.get("result_metadata"))}
                {records_html}
              </div>
            </div>
            """
        )

    return f'<div class="timeline">{"".join(items)}</div>'


def _severity_chart(counts: Counter[str]) -> str:
    ordered = Counter({key: counts.get(key, 0) for key in ("critical", "high", "medium", "low", "info", "unknown")})
    return _bar_chart(ordered, "severity")


def _bar_chart(counts: Counter[str], label: str) -> str:
    if not counts:
        return '<p class="muted">No data yet.</p>'

    max_count = max(counts.values()) or 1
    rows = []
    for name, count in counts.items():
        width = int((count / max_count) * 100)
        rows.append(
            f"""
            <div class="bar-row">
              <div>{_e(name)}</div>
              <div class="bar-track"><div class="bar-fill" style="width: {width}%"></div></div>
              <div>{count}</div>
            </div>
            """
        )
    return "".join(rows)


def _json_block(value: Any) -> str:
    return f"<pre>{_e(json.dumps(value or {}, indent=2, sort_keys=True, default=str))}</pre>"


def _badge(value: Any) -> str:
    text = str(value or "unknown")
    class_name = "".join(ch if ch.isalnum() else "_" for ch in text.lower())
    return f'<span class="badge {class_name}">{_e(text)}</span>'


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


app = create_app()
