"""Evidence file index for SABER."""

from __future__ import annotations

import hashlib
import json
import mimetypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


class EvidenceIndex:
    """Persist evidence file metadata and integrity hashes."""

    def __init__(self, connection: Any) -> None:
        """Initialize evidence index."""

        self.connection = connection

    def add_evidence(
        self,
        session_id: str,
        path: str | Path,
        title: str,
        tool_name: str | None = None,
        step_id: str | None = None,
        action: str | None = None,
        mime_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Add evidence file metadata and return evidence ID."""

        if not session_id:
            raise ValueError("session_id cannot be empty.")
        if not title:
            raise ValueError("title cannot be empty.")

        evidence_path = Path(path)
        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence file does not exist: {evidence_path}")
        if not evidence_path.is_file():
            raise ValueError(f"Evidence path is not a file: {evidence_path}")

        evidence_id = f"evidence_{uuid4().hex[:12]}"
        resolved_mime_type = mime_type or self.detect_mime_type(evidence_path)
        sha256 = self.compute_sha256(evidence_path)
        size_bytes = evidence_path.stat().st_size

        self.connection.execute(
            """
            INSERT INTO evidence (
                evidence_id, session_id, step_id, tool_name, action, title, path,
                mime_type, sha256, size_bytes, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                session_id,
                step_id,
                tool_name,
                action,
                title,
                str(evidence_path),
                resolved_mime_type,
                sha256,
                size_bytes,
                self._json(metadata or {}),
                self._now(),
            ),
        )

        return evidence_id

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        """Get evidence by ID."""

        row = self.connection.query_one(
            "SELECT * FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        )
        return self._decode_row(row)

    def list_evidence(self, session_id: str) -> list[dict[str, Any]]:
        """List all evidence for a session."""

        rows = self.connection.query_all(
            """
            SELECT * FROM evidence
            WHERE session_id = ?
            ORDER BY created_at ASC
            """,
            (session_id,),
        )
        return [self._decode_row(row) for row in rows]

    def list_step_evidence(self, session_id: str, step_id: str) -> list[dict[str, Any]]:
        """List evidence for one step."""

        rows = self.connection.query_all(
            """
            SELECT * FROM evidence
            WHERE session_id = ? AND step_id = ?
            ORDER BY created_at ASC
            """,
            (session_id, step_id),
        )
        return [self._decode_row(row) for row in rows]

    def verify_evidence(self, evidence_id: str) -> bool:
        """Verify evidence file still matches stored hash and size."""

        evidence = self.get_evidence(evidence_id)
        if not evidence:
            raise KeyError(f"Evidence not found: {evidence_id}")

        path = Path(evidence["path"])
        if not path.exists() or not path.is_file():
            return False

        current_size = path.stat().st_size
        if current_size != evidence["size_bytes"]:
            return False

        current_sha256 = self.compute_sha256(path)
        return current_sha256 == evidence["sha256"]

    @staticmethod
    def compute_sha256(path: str | Path) -> str:
        """Compute SHA-256 digest for a file."""

        file_path = Path(path)
        digest = hashlib.sha256()

        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def detect_mime_type(path: str | Path) -> str:
        """Best-effort MIME type detection."""

        file_path = Path(path)
        guessed, _ = mimetypes.guess_type(str(file_path))
        return guessed or "application/octet-stream"

    @staticmethod
    def _json(value: Any) -> str:
        """Serialize JSON."""

        return json.dumps(value, sort_keys=True, default=str)

    @classmethod
    def _decode_row(cls, row: Any) -> dict[str, Any] | None:
        """Decode SQLite row."""

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

        return data

    @staticmethod
    def _now() -> str:
        """Current UTC timestamp."""

        return datetime.now(UTC).isoformat()
