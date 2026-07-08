"""Session storage for SABER."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


class SessionStore:
    """Persist sessions, plans, steps, approvals, step records, and report artifacts."""

    def __init__(self, connection: Any) -> None:
        """Initialize store."""

        self.connection = connection

    def create_session(self, session: Any) -> None:
        """Create or replace a mission session."""

        session_id = self._get_attr(session, "session_id")
        mission_name = self._get_attr(session, "mission_name")
        status = self._enum_value(self._get_attr(session, "status", "created"))
        metadata = self._get_attr(session, "metadata", {}) or {}

        if not session_id:
            raise ValueError("session_id cannot be empty.")
        if not mission_name:
            raise ValueError("mission_name cannot be empty.")

        now = self._now()
        self.connection.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, mission_name, status, created_at, updated_at, metadata_json
            )
            VALUES (?, ?, ?, COALESCE((SELECT created_at FROM sessions WHERE session_id = ?), ?), ?, ?)
            """,
            (
                session_id,
                mission_name,
                status,
                session_id,
                now,
                now,
                self._json(metadata),
            ),
        )

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get a session by ID."""

        row = self.connection.query_one(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        )
        return self._decode_row(row)

    def update_session_status(
        self,
        session_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update session status and optionally merge metadata."""

        existing = self.get_session(session_id)
        if not existing:
            raise KeyError(f"Session not found: {session_id}")

        merged_metadata = dict(existing.get("metadata", {}))
        if metadata:
            merged_metadata.update(metadata)

        self.connection.execute(
            """
            UPDATE sessions
            SET status = ?, updated_at = ?, metadata_json = ?
            WHERE session_id = ?
            """,
            (status, self._now(), self._json(merged_metadata), session_id),
        )

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        """List recent sessions."""

        rows = self.connection.query_all(
            """
            SELECT * FROM sessions
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [self._decode_row(row) for row in rows]

    def save_plan(self, session_id: str, plan: Any) -> None:
        """Persist execution plan and its steps."""

        plan_id = self._get_attr(plan, "plan_id")
        mission_name = self._get_attr(plan, "mission_name")
        created_at = self._get_attr(plan, "created_at", None) or self._now()
        updated_at = self._get_attr(plan, "updated_at", None) or self._now()
        plan_json = self._object_to_dict(plan)

        if not plan_id:
            raise ValueError("plan_id cannot be empty.")

        with self.connection.transaction():
            self.connection.execute(
                """
                INSERT OR REPLACE INTO execution_plans (
                    plan_id, session_id, mission_name, created_at, updated_at, plan_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    session_id,
                    mission_name,
                    self._datetime_to_str(created_at),
                    self._datetime_to_str(updated_at),
                    self._json(plan_json),
                ),
            )

            for step in self._get_attr(plan, "steps", []) or []:
                self.save_step(session_id, step)

    def get_plan(self, session_id: str) -> dict[str, Any] | None:
        """Get latest plan for session."""

        row = self.connection.query_one(
            """
            SELECT * FROM execution_plans
            WHERE session_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (session_id,),
        )
        return self._decode_row(row)

    def save_step(self, session_id: str, step: Any) -> None:
        """Persist one execution step."""

        step_id = self._get_attr(step, "step_id")
        if not step_id:
            raise ValueError("step_id cannot be empty.")

        self.connection.execute(
            """
            INSERT OR REPLACE INTO execution_steps (
                step_id, session_id, agent_name, objective, phase, target_json, status,
                depends_on_json, metadata_json, result_metadata_json, created_at, updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                COALESCE((SELECT created_at FROM execution_steps WHERE session_id = ? AND step_id = ?), ?),
                ?
            )
            """,
            (
                step_id,
                session_id,
                self._get_attr(step, "agent_name"),
                self._get_attr(step, "objective"),
                self._enum_value(self._get_attr(step, "phase")),
                self._json(self._object_to_dict(self._get_attr(step, "target", None))),
                self._enum_value(self._get_attr(step, "status", "pending")),
                self._json(self._get_attr(step, "depends_on", []) or []),
                self._json(self._get_attr(step, "metadata", {}) or {}),
                self._json(self._get_attr(step, "result_metadata", {}) or {}),
                session_id,
                step_id,
                self._now(),
                self._now(),
            ),
        )

    def update_step_status(
        self,
        session_id: str,
        step_id: str,
        status: str,
        result_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update execution step status."""

        existing = self.connection.query_one(
            "SELECT result_metadata_json FROM execution_steps WHERE session_id = ? AND step_id = ?",
            (session_id, step_id),
        )
        if not existing:
            raise KeyError(f"Execution step not found: {session_id}/{step_id}")

        metadata = self._json_loads(existing["result_metadata_json"])
        if result_metadata:
            metadata.update(result_metadata)

        self.connection.execute(
            """
            UPDATE execution_steps
            SET status = ?, result_metadata_json = ?, updated_at = ?
            WHERE session_id = ? AND step_id = ?
            """,
            (status, self._json(metadata), self._now(), session_id, step_id),
        )

    def list_steps(self, session_id: str) -> list[dict[str, Any]]:
        """List execution steps for a session."""

        rows = self.connection.query_all(
            """
            SELECT * FROM execution_steps
            WHERE session_id = ?
            ORDER BY created_at ASC
            """,
            (session_id,),
        )
        return [self._decode_row(row) for row in rows]

    def save_step_record(self, session_id: str, record: Any) -> str:
        """Persist one step run record."""

        record_id = f"record_{uuid4().hex[:12]}"
        step_id = self._get_attr(record, "step_id")
        agent_name = self._get_attr(record, "agent_name")
        status = self._enum_value(self._get_attr(record, "status"))
        handoff_agent = self._get_attr(record, "handoff_agent", None)
        requires_approval = bool(self._get_attr(record, "requires_approval", False))
        record_json = self._object_to_dict(record)

        self.connection.execute(
            """
            INSERT INTO step_records (
                record_id, session_id, step_id, agent_name, status, handoff_agent,
                requires_approval, record_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                session_id,
                step_id,
                agent_name,
                status,
                handoff_agent,
                int(requires_approval),
                self._json(record_json),
                self._now(),
            ),
        )
        return record_id

    def list_step_records(self, session_id: str) -> list[dict[str, Any]]:
        """List step records for a session."""

        rows = self.connection.query_all(
            """
            SELECT * FROM step_records
            WHERE session_id = ?
            ORDER BY created_at ASC
            """,
            (session_id,),
        )
        return [self._decode_row(row) for row in rows]

    def create_approval_request(
        self,
        session_id: str,
        step_id: str,
        reason: str,
        requested_action: dict[str, Any] | Any,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create an approval request."""

        approval_id = f"approval_{uuid4().hex[:12]}"
        self.connection.execute(
            """
            INSERT INTO approvals (
                approval_id, session_id, step_id, status, reason, requested_action_json,
                decision, requested_at, resolved_at, resolved_by, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, ?)
            """,
            (
                approval_id,
                session_id,
                step_id,
                "pending",
                reason,
                self._json(self._object_to_dict(requested_action)),
                self._now(),
                self._json(metadata or {}),
            ),
        )
        return approval_id

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        resolved_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Resolve an approval request."""

        row = self.connection.query_one(
            "SELECT metadata_json FROM approvals WHERE approval_id = ?",
            (approval_id,),
        )
        if not row:
            raise KeyError(f"Approval not found: {approval_id}")

        existing_metadata = self._json_loads(row["metadata_json"])
        if metadata:
            existing_metadata.update(metadata)

        status = "approved" if decision == "approved" else "denied" if decision == "denied" else decision
        self.connection.execute(
            """
            UPDATE approvals
            SET status = ?, decision = ?, resolved_at = ?, resolved_by = ?, metadata_json = ?
            WHERE approval_id = ?
            """,
            (
                status,
                decision,
                self._now(),
                resolved_by,
                self._json(existing_metadata),
                approval_id,
            ),
        )

    def list_pending_approvals(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """List pending approval requests."""

        if session_id:
            rows = self.connection.query_all(
                """
                SELECT * FROM approvals
                WHERE status = 'pending' AND session_id = ?
                ORDER BY requested_at ASC
                """,
                (session_id,),
            )
        else:
            rows = self.connection.query_all(
                """
                SELECT * FROM approvals
                WHERE status = 'pending'
                ORDER BY requested_at ASC
                """,
                (),
            )

        return [self._decode_row(row) for row in rows]

    def save_report_artifact(
        self,
        session_id: str,
        report_type: str,
        path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Persist report artifact metadata."""

        report_path = Path(path)
        report_id = f"report_artifact_{uuid4().hex[:12]}"
        sha256 = self._sha256(report_path) if report_path.exists() else None
        size_bytes = report_path.stat().st_size if report_path.exists() else None

        self.connection.execute(
            """
            INSERT INTO report_artifacts (
                report_id, session_id, report_type, path, sha256, size_bytes,
                metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                session_id,
                report_type,
                str(report_path),
                sha256,
                size_bytes,
                self._json(metadata or {}),
                self._now(),
            ),
        )
        return report_id

    def list_report_artifacts(self, session_id: str) -> list[dict[str, Any]]:
        """List report artifacts for a session."""

        rows = self.connection.query_all(
            """
            SELECT * FROM report_artifacts
            WHERE session_id = ?
            ORDER BY created_at ASC
            """,
            (session_id,),
        )
        return [self._decode_row(row) for row in rows]

    @staticmethod
    def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
        """Get attribute or dict key."""

        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    @classmethod
    def _object_to_dict(cls, value: Any) -> Any:
        """Convert object to JSON-compatible structure."""

        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            return [cls._object_to_dict(item) for item in value]
        if isinstance(value, tuple):
            return [cls._object_to_dict(item) for item in value]
        if isinstance(value, dict):
            return {str(key): cls._object_to_dict(item) for key, item in value.items()}
        if hasattr(value, "to_dict"):
            return cls._object_to_dict(value.to_dict())
        if hasattr(value, "model_dump"):
            return cls._object_to_dict(value.model_dump(mode="json"))
        if hasattr(value, "value"):
            return value.value
        return str(value)

    @staticmethod
    def _enum_value(value: Any) -> str:
        """Return enum value or string."""

        if value is None:
            return ""
        return str(getattr(value, "value", value))

    @staticmethod
    def _json(value: Any) -> str:
        """Serialize JSON."""

        return json.dumps(value, sort_keys=True, default=str)

    @staticmethod
    def _json_loads(value: str | None) -> dict[str, Any]:
        """Load JSON object."""

        if not value:
            return {}
        loaded = json.loads(value)
        return loaded if isinstance(loaded, dict) else {}

    @classmethod
    def _decode_row(cls, row: Any) -> dict[str, Any] | None:
        """Decode sqlite row to dict."""

        if row is None:
            return None

        data = dict(row)
        for key in list(data.keys()):
            if key.endswith("_json"):
                decoded_key = key[:-5]
                raw = data.pop(key)
                try:
                    data[decoded_key] = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    data[decoded_key] = raw

        if "requires_approval" in data:
            data["requires_approval"] = bool(data["requires_approval"])

        return data

    @staticmethod
    def _datetime_to_str(value: Any) -> str:
        """Convert datetime-like value to string."""

        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    @staticmethod
    def _now() -> str:
        """Current UTC timestamp."""

        return datetime.now(UTC).isoformat()

    @staticmethod
    def _sha256(path: Path) -> str:
        """Compute sha256."""

        import hashlib

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
