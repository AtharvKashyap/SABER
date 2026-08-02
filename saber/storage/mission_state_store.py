"""Persistence for MissionState snapshots."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from saber.models.mission_state import MissionState


class MissionStateStore:
    """Persist and load MissionState as a JSON snapshot per session."""

    def __init__(self, connection: Any) -> None:
        """Initialize store."""

        self.connection = connection

    def save(self, state: MissionState) -> None:
        """Upsert the working-memory snapshot for a session."""

        if not state.session_id:
            raise ValueError("MissionState.session_id cannot be empty.")

        self.connection.execute(
            """
            INSERT OR REPLACE INTO mission_states (session_id, state_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (
                state.session_id,
                state.model_dump_json(),
                datetime.now(UTC).isoformat(),
            ),
        )

    def snapshot(self, state: MissionState) -> None:
        """Alias used by the mission loop after every merge."""

        self.save(state)

    def load(self, session_id: str) -> MissionState | None:
        """Load the latest snapshot for a session, or None."""

        row = self.connection.query_one(
            "SELECT state_json FROM mission_states WHERE session_id = ?",
            (session_id,),
        )
        if row is None:
            return None
        return MissionState.model_validate_json(row["state_json"])

    def summaries(self) -> dict[str, dict[str, Any]]:
        """Return a light per-session digest of every stored snapshot.

        The mission list needs the target and step count for each session, but
        those live in the snapshot rather than the ``sessions`` row. Validating
        every snapshot into a full ``MissionState`` just to read two fields is
        wasteful on a long engagement history, so this reads the JSON directly.
        """

        rows = self.connection.query_all(
            "SELECT session_id, state_json FROM mission_states", ()
        )

        digests: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                data = json.loads(row["state_json"])
            except (TypeError, ValueError):
                continue
            target = data.get("target") or {}
            digests[row["session_id"]] = {
                "target": target.get("value") if isinstance(target, dict) else None,
                "step_count": data.get("step_count") or 0,
                "current_phase": data.get("current_phase"),
                "objective_met": bool(data.get("objective_met")),
                "stop_reason": data.get("stop_reason"),
            }
        return digests
