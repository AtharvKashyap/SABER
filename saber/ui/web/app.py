"""SABER FastAPI web application."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.storage.session_store import SessionStore
from saber.ui.web.routers import findings, reports, sessions


PUBLIC_PATHS = {
    "/",
    "/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}


def create_app(
    db_path: str | Path = "runs/saber.db",
    reports_dir: str | Path = "runs/reports",
    allow_origins: list[str] | None = None,
    api_key: str | None = None,
    require_auth: bool | None = None,
) -> FastAPI:
    """Create and configure SABER web app.

    Authentication behavior:
    - If api_key is provided, API authentication is required.
    - If SABER_API_KEY is set, API authentication is required.
    - If neither is set, auth is disabled for local development.
    """

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

    app.state.db_path = str(db_path)
    app.state.reports_dir = str(reports_root)
    app.state.auth_required = auth_required
    app.state.api_key = resolved_api_key
    app.state.storage_connection = connection
    app.state.session_store = SessionStore(connection)
    app.state.finding_store = FindingStore(connection)
    app.state.evidence_index = EvidenceIndex(connection)
    app.state.graph_store = GraphStore(connection)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: Any) -> Any:
        """Apply API-key auth and security headers."""

        if app.state.auth_required and request.url.path not in PUBLIC_PATHS:
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
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
        return response

    app.include_router(sessions.router)
    app.include_router(findings.router)
    app.include_router(reports.router)

    @app.get("/")
    def root() -> dict[str, Any]:
        """Return API landing payload."""

        return {
            "name": "SABER",
            "status": "ok",
            "auth_required": app.state.auth_required,
            "routes": {
                "health": "/health",
                "sessions": "/sessions",
                "findings": "/findings",
                "reports": "/reports",
            },
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Return health status."""

        storage_ok = True
        storage_error = None

        try:
            app.state.storage_connection.query_one("SELECT 1 AS ok")
        except Exception as exc:  # pragma: no cover - defensive health path
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


app = create_app()
