"""Finding and observation storage for SABER."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


class FindingStore:
    """Persist normalized findings and observations."""

    VALID_STATUSES = {
        "new",
        "confirmed",
        "false_positive",
        "accepted_risk",
        "remediated",
        "retest_needed",
        "closed",
    }

    def __init__(self, connection: Any) -> None:
        """Initialize store."""

        self.connection = connection

    def save_finding(
        self,
        session_id: str,
        finding: Any,
        step_id: str | None = None,
        evidence_id: str | None = None,
        status: str = "new",
    ) -> str:
        """Persist a finding and return finding ID."""

        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {status}")

        normalized = self._normalize_finding(finding)
        fingerprint = self._finding_fingerprint(session_id, normalized)

        existing = self.connection.query_one(
            """
            SELECT finding_id FROM findings
            WHERE session_id = ? AND fingerprint = ?
            """,
            (session_id, fingerprint),
        )
        if existing:
            return existing["finding_id"]

        finding_id = f"finding_{uuid4().hex[:12]}"
        now = self._now()

        self.connection.execute(
            """
            INSERT INTO findings (
                finding_id, session_id, step_id, evidence_id, title, severity,
                description, source_tool, status, fingerprint, evidence_json,
                references_json, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                session_id,
                step_id,
                evidence_id,
                normalized["title"],
                normalized["severity"],
                normalized["description"],
                normalized.get("source_tool"),
                status,
                fingerprint,
                self._json(normalized.get("evidence", {})),
                self._json(normalized.get("references", [])),
                self._json(normalized.get("metadata", {})),
                now,
                now,
            ),
        )
        return finding_id

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Get finding by ID."""

        row = self.connection.query_one(
            "SELECT * FROM findings WHERE finding_id = ?",
            (finding_id,),
        )
        return self._decode_row(row)

    def list_findings(
        self,
        session_id: str,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List findings for session."""

        query = "SELECT * FROM findings WHERE session_id = ?"
        params: list[Any] = [session_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += """
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    WHEN 'info' THEN 4
                    ELSE 5
                END,
                created_at ASC
        """

        rows = self.connection.query_all(query, tuple(params))
        return [self._decode_row(row) for row in rows]

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update finding status and optionally merge metadata."""

        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {status}")

        finding = self.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Finding not found: {finding_id}")

        merged_metadata = dict(finding.get("metadata", {}) or {})
        if metadata:
            merged_metadata.update(metadata)

        self.connection.execute(
            """
            UPDATE findings
            SET status = ?, metadata_json = ?, updated_at = ?
            WHERE finding_id = ?
            """,
            (status, self._json(merged_metadata), self._now(), finding_id),
        )

    def deduplicate_findings(self, session_id: str) -> list[dict[str, Any]]:
        """Return duplicate finding groups by fingerprint.

        Inserts already deduplicate, so this is mainly an audit helper.
        """

        rows = self.connection.query_all(
            """
            SELECT fingerprint, COUNT(*) AS count
            FROM findings
            WHERE session_id = ?
            GROUP BY fingerprint
            HAVING COUNT(*) > 1
            ORDER BY count DESC
            """,
            (session_id,),
        )
        return [dict(row) for row in rows]

    def save_observation(
        self,
        session_id: str,
        observation: Any,
        step_id: str | None = None,
        evidence_id: str | None = None,
    ) -> str:
        """Persist an observation and return observation ID."""

        normalized = self._normalize_observation(observation)
        observation_id = f"observation_{uuid4().hex[:12]}"

        self.connection.execute(
            """
            INSERT INTO observations (
                observation_id, session_id, step_id, evidence_id, kind, summary,
                source_tool, data_json, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                session_id,
                step_id,
                evidence_id,
                normalized["kind"],
                normalized["summary"],
                normalized.get("source_tool"),
                self._json(normalized.get("data", {})),
                self._json(normalized.get("metadata", {})),
                self._now(),
            ),
        )
        return observation_id

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        """Get observation by ID."""

        row = self.connection.query_one(
            "SELECT * FROM observations WHERE observation_id = ?",
            (observation_id,),
        )
        return self._decode_row(row)

    def list_observations(
        self,
        session_id: str,
        kind: str | None = None,
        source_tool: str | None = None,
    ) -> list[dict[str, Any]]:
        """List observations for session."""

        query = "SELECT * FROM observations WHERE session_id = ?"
        params: list[Any] = [session_id]

        if kind:
            query += " AND kind = ?"
            params.append(kind)

        if source_tool:
            query += " AND source_tool = ?"
            params.append(source_tool)

        query += " ORDER BY created_at ASC"

        rows = self.connection.query_all(query, tuple(params))
        return [self._decode_row(row) for row in rows]

    def _normalize_finding(self, finding: Any) -> dict[str, Any]:
        """Normalize finding-like object."""

        if isinstance(finding, dict):
            data = dict(finding)
        else:
            data = {
                "title": getattr(finding, "title", None),
                "severity": getattr(finding, "severity", None),
                "description": getattr(finding, "description", None),
                "source_tool": getattr(finding, "source_tool", None),
                "evidence": getattr(finding, "evidence", {}),
                "references": getattr(finding, "references", []),
                "metadata": getattr(finding, "metadata", {}),
            }

        title = str(data.get("title") or "Finding")
        description = str(data.get("description") or "No description provided.")
        severity = self._severity(data.get("severity"))
        evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
        references = data.get("references") or []
        if isinstance(references, str):
            references = [references]
        references = [str(reference) for reference in references]
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}

        return {
            "title": title,
            "severity": severity,
            "description": description,
            "source_tool": data.get("source_tool"),
            "evidence": evidence,
            "references": references,
            "metadata": metadata,
        }

    def _normalize_observation(self, observation: Any) -> dict[str, Any]:
        """Normalize observation-like object."""

        if isinstance(observation, dict):
            data = dict(observation)
        else:
            data = {
                "kind": getattr(observation, "kind", None),
                "summary": getattr(observation, "summary", None),
                "source_tool": getattr(observation, "source_tool", None)
                or getattr(observation, "tool_name", None),
                "data": getattr(observation, "data", {}),
                "metadata": getattr(observation, "metadata", {}),
            }

        return {
            "kind": str(data.get("kind") or "generic"),
            "summary": str(data.get("summary") or data.get("message") or "Observation."),
            "source_tool": data.get("source_tool") or data.get("tool_name"),
            "data": data.get("data") if isinstance(data.get("data"), dict) else {},
            "metadata": data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
        }

    @classmethod
    def _finding_fingerprint(cls, session_id: str, finding: dict[str, Any]) -> str:
        """Build deterministic finding fingerprint."""

        evidence = finding.get("evidence", {}) or {}
        fingerprint_payload = {
            "session_id": session_id,
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "source_tool": finding.get("source_tool"),
            "template_id": evidence.get("template_id"),
            "matched_at": evidence.get("matched_at"),
            "host": evidence.get("host"),
            "ip": evidence.get("ip"),
            "port": evidence.get("port"),
        }
        raw = json.dumps(fingerprint_payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _severity(value: Any) -> str:
        """Normalize severity."""

        raw = getattr(value, "value", value)
        if raw is None:
            return "unknown"

        normalized = str(raw).strip().lower()
        mapping = {
            "info": "info",
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "med": "medium",
            "high": "high",
            "critical": "critical",
            "crit": "critical",
            "unknown": "unknown",
        }
        return mapping.get(normalized, "unknown")

    @staticmethod
    def _json(value: Any) -> str:
        """Serialize JSON."""

        return json.dumps(value, sort_keys=True, default=str)

    @classmethod
    def _decode_row(cls, row: Any) -> dict[str, Any] | None:
        """Decode sqlite row."""

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
