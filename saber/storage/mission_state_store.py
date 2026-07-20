"""Persistence for MissionState snapshots."""

from __future__ import annotations

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
