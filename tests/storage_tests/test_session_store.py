"""Tests for SessionStore."""

from __future__ import annotations

import contextlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from saber.storage.session_store import SessionStore


class FakeConnection:
    """Small sqlite test connection with the store interface."""

    def __init__(self) -> None:
        """Initialize in-memory sqlite DB."""

        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        """Execute SQL."""

        return self.conn.execute(sql, params)

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        """Query one row."""

        return self.conn.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        """Query all rows."""

        return list(self.conn.execute(sql, params).fetchall())

    @contextlib.contextmanager
    def transaction(self):
        """Transaction context."""

        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def _create_schema(self) -> None:
        """Create storage schema needed by SessionStore."""

        self.conn.executescript(
            """
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                mission_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );

            CREATE TABLE execution_plans (
                plan_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                mission_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                plan_json TEXT NOT NULL
            );

            CREATE TABLE execution_steps (
                step_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                objective TEXT NOT NULL,
                phase TEXT NOT NULL,
                target_json TEXT,
                status TEXT NOT NULL,
                depends_on_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                result_metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (session_id, step_id)
            );

            CREATE TABLE step_records (
                record_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                status TEXT NOT NULL,
                handoff_agent TEXT,
                requires_approval INTEGER NOT NULL,
                record_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_action_json TEXT NOT NULL,
                decision TEXT,
                requested_at TEXT NOT NULL,
                resolved_at TEXT,
                resolved_by TEXT,
                metadata_json TEXT NOT NULL
            );

            CREATE TABLE report_artifacts (
                report_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                report_type TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                size_bytes INTEGER,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@dataclass
class FakeSession:
    """Fake mission session."""

    session_id: str = "session_1"
    mission_name: str = "Storage Test Mission"
    status: str = "created"
    metadata: dict[str, Any] = field(default_factory=lambda: {"owner": "unit-test"})


@dataclass
class FakeTarget:
    """Fake target."""

    type: str = "host"
    value: str = "example.com"

    def to_dict(self) -> dict[str, Any]:
        """Serialize target."""

        return {"type": self.type, "value": self.value}


@dataclass
class FakeStep:
    """Fake execution step."""

    step_id: str
    agent_name: str
    objective: str = "Run step."
    phase: str = "recon"
    target: FakeTarget = field(default_factory=FakeTarget)
    status: str = "pending"
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    result_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize step."""

        return {
            "step_id": self.step_id,
            "agent_name": self.agent_name,
            "objective": self.objective,
            "phase": self.phase,
            "target": self.target.to_dict(),
            "status": self.status,
            "depends_on": self.depends_on,
            "metadata": self.metadata,
            "result_metadata": self.result_metadata,
        }


@dataclass
class FakePlan:
    """Fake execution plan."""

    plan_id: str = "plan_1"
    mission_name: str = "Storage Test Mission"
    created_at: str = "2026-01-01T00:00:00+00:00"
    updated_at: str = "2026-01-01T00:00:00+00:00"
    steps: list[FakeStep] = field(default_factory=lambda: [FakeStep("recon", "recon_agent")])

    def to_dict(self) -> dict[str, Any]:
        """Serialize plan."""

        return {
            "plan_id": self.plan_id,
            "mission_name": self.mission_name,
            "steps": [step.to_dict() for step in self.steps],
        }


@pytest.fixture
def store() -> SessionStore:
    """Create session store."""

    return SessionStore(FakeConnection())


class TestSessionStore:
    """Validate SessionStore."""

    def test_create_and_get_session(self, store: SessionStore) -> None:
        """Session should be saved and returned."""

        store.create_session(FakeSession())

        session = store.get_session("session_1")

        assert session is not None
        assert session["session_id"] == "session_1"
        assert session["mission_name"] == "Storage Test Mission"
        assert session["status"] == "created"
        assert session["metadata"] == {"owner": "unit-test"}

    def test_create_session_validates_id(self, store: SessionStore) -> None:
        """Empty session ID should raise."""

        with pytest.raises(ValueError, match="session_id cannot be empty"):
            store.create_session(FakeSession(session_id=""))

    def test_create_session_validates_mission_name(self, store: SessionStore) -> None:
        """Empty mission name should raise."""

        with pytest.raises(ValueError, match="mission_name cannot be empty"):
            store.create_session(FakeSession(mission_name=""))

    def test_update_session_status_merges_metadata(self, store: SessionStore) -> None:
        """Session status update should merge metadata."""

        store.create_session(FakeSession())

        store.update_session_status("session_1", "running", {"phase": "recon"})

        session = store.get_session("session_1")
        assert session["status"] == "running"
        assert session["metadata"] == {"owner": "unit-test", "phase": "recon"}

    def test_update_missing_session_raises(self, store: SessionStore) -> None:
        """Updating missing session should raise."""

        with pytest.raises(KeyError, match="Session not found"):
            store.update_session_status("missing", "running")

    def test_list_sessions(self, store: SessionStore) -> None:
        """Sessions should list."""

        store.create_session(FakeSession(session_id="session_1", mission_name="One"))
        store.create_session(FakeSession(session_id="session_2", mission_name="Two"))

        sessions = store.list_sessions()

        assert len(sessions) == 2
        assert {session["session_id"] for session in sessions} == {"session_1", "session_2"}

    def test_save_and_get_plan_saves_steps(self, store: SessionStore) -> None:
        """Plan and steps should persist."""

        store.create_session(FakeSession())
        plan = FakePlan(
            steps=[
                FakeStep("planner", "planner_agent"),
                FakeStep("recon", "recon_agent", depends_on=["planner"]),
            ]
        )

        store.save_plan("session_1", plan)

        saved_plan = store.get_plan("session_1")
        steps = store.list_steps("session_1")

        assert saved_plan is not None
        assert saved_plan["plan_id"] == "plan_1"
        assert saved_plan["plan"]["plan_id"] == "plan_1"
        assert len(steps) == 2
        assert steps[0]["step_id"] == "planner"
        assert steps[1]["depends_on"] == ["planner"]

    def test_save_step_validates_step_id(self, store: SessionStore) -> None:
        """Empty step ID should raise."""

        with pytest.raises(ValueError, match="step_id cannot be empty"):
            store.save_step("session_1", FakeStep("", "agent"))

    def test_update_step_status(self, store: SessionStore) -> None:
        """Step status should update and merge result metadata."""

        store.save_step("session_1", FakeStep("recon", "recon_agent", result_metadata={"old": True}))

        store.update_step_status("session_1", "recon", "completed", {"new": True})

        steps = store.list_steps("session_1")
        assert steps[0]["status"] == "completed"
        assert steps[0]["result_metadata"] == {"old": True, "new": True}

    def test_update_missing_step_raises(self, store: SessionStore) -> None:
        """Updating missing step should raise."""

        with pytest.raises(KeyError, match="Execution step not found"):
            store.update_step_status("session_1", "missing", "completed")

    def test_save_and_list_step_records(self, store: SessionStore) -> None:
        """Step records should persist."""

        record_id = store.save_step_record(
            "session_1",
            {
                "step_id": "recon",
                "agent_name": "recon_agent",
                "status": "completed",
                "handoff_agent": None,
                "requires_approval": False,
                "metadata": {"ok": True},
            },
        )

        records = store.list_step_records("session_1")

        assert record_id.startswith("record_")
        assert len(records) == 1
        assert records[0]["step_id"] == "recon"
        assert records[0]["requires_approval"] is False
        assert records[0]["record"]["metadata"] == {"ok": True}

    def test_create_list_and_resolve_approval(self, store: SessionStore) -> None:
        """Approval lifecycle should persist."""

        approval_id = store.create_approval_request(
            session_id="session_1",
            step_id="exploit",
            reason="Exploit execution requires approval.",
            requested_action={"tool": "metasploit", "action": "run"},
            metadata={"risk": "high"},
        )

        pending = store.list_pending_approvals("session_1")
        assert len(pending) == 1
        assert pending[0]["approval_id"] == approval_id
        assert pending[0]["requested_action"] == {"tool": "metasploit", "action": "run"}

        store.resolve_approval(
            approval_id,
            decision="approved",
            resolved_by="analyst",
            metadata={"ticket": "APPROVED-1"},
        )

        assert store.list_pending_approvals("session_1") == []

        row = store.connection.query_one("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        resolved = store._decode_row(row)
        assert resolved["status"] == "approved"
        assert resolved["decision"] == "approved"
        assert resolved["resolved_by"] == "analyst"
        assert resolved["metadata"] == {"risk": "high", "ticket": "APPROVED-1"}

    def test_resolve_missing_approval_raises(self, store: SessionStore) -> None:
        """Resolving missing approval should raise."""

        with pytest.raises(KeyError, match="Approval not found"):
            store.resolve_approval("missing", "approved")

    def test_save_and_list_report_artifacts(self, store: SessionStore, tmp_path: Path) -> None:
        """Report artifacts should persist with hash and size."""

        report = tmp_path / "report.json"
        report.write_text('{"ok": true}')

        report_id = store.save_report_artifact(
            "session_1",
            report_type="json",
            path=report,
            metadata={"format": "json"},
        )

        artifacts = store.list_report_artifacts("session_1")

        assert report_id.startswith("report_artifact_")
        assert len(artifacts) == 1
        assert artifacts[0]["report_type"] == "json"
        assert artifacts[0]["path"] == str(report)
        assert artifacts[0]["sha256"]
        assert artifacts[0]["size_bytes"] == report.stat().st_size
        assert artifacts[0]["metadata"] == {"format": "json"}
