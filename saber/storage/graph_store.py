"""AD graph storage for SABER."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


class GraphStore:
    """Persist AD graph nodes, edges, and attack paths."""

    def __init__(self, connection: Any) -> None:
        """Initialize store."""

        self.connection = connection

    def upsert_node(
        self,
        session_id: str,
        name: str,
        kind: str = "unknown",
        labels: list[str] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Insert or update a graph node and return node ID."""

        if not name:
            raise ValueError("node name cannot be empty.")

        kind = kind or "unknown"
        existing = self.connection.query_one(
            """
            SELECT node_id FROM graph_nodes
            WHERE session_id = ? AND name = ? AND kind = ?
            """,
            (session_id, name, kind),
        )

        if existing:
            node_id = existing["node_id"]
            self.connection.execute(
                """
                UPDATE graph_nodes
                SET labels_json = ?, properties_json = ?, updated_at = ?
                WHERE node_id = ?
                """,
                (
                    self._json(labels or []),
                    self._json(properties or {}),
                    self._now(),
                    node_id,
                ),
            )
            return node_id

        node_id = f"node_{uuid4().hex[:12]}"
        now = self._now()
        self.connection.execute(
            """
            INSERT INTO graph_nodes (
                node_id, session_id, name, kind, labels_json, properties_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node_id,
                session_id,
                name,
                kind,
                self._json(labels or []),
                self._json(properties or {}),
                now,
                now,
            ),
        )
        return node_id

    def upsert_edge(
        self,
        session_id: str,
        source: str,
        target: str,
        relationship: str,
        properties: dict[str, Any] | None = None,
        source_kind: str = "unknown",
        target_kind: str = "unknown",
    ) -> str:
        """Insert or update a graph edge and return edge ID."""

        if not source:
            raise ValueError("source cannot be empty.")
        if not target:
            raise ValueError("target cannot be empty.")
        if not relationship:
            raise ValueError("relationship cannot be empty.")

        source_node_id = self.upsert_node(
            session_id=session_id,
            name=source,
            kind=source_kind,
            properties={"name": source, **(properties or {}).get("source_properties", {})}
            if isinstance((properties or {}).get("source_properties", {}), dict)
            else {"name": source},
        )
        target_node_id = self.upsert_node(
            session_id=session_id,
            name=target,
            kind=target_kind,
            properties={"name": target, **(properties or {}).get("target_properties", {})}
            if isinstance((properties or {}).get("target_properties", {}), dict)
            else {"name": target},
        )

        existing = self.connection.query_one(
            """
            SELECT edge_id FROM graph_edges
            WHERE session_id = ?
              AND source_node_id = ?
              AND target_node_id = ?
              AND relationship = ?
            """,
            (session_id, source_node_id, target_node_id, relationship),
        )

        if existing:
            edge_id = existing["edge_id"]
            self.connection.execute(
                """
                UPDATE graph_edges
                SET properties_json = ?
                WHERE edge_id = ?
                """,
                (self._json(properties or {}), edge_id),
            )
            return edge_id

        edge_id = f"edge_{uuid4().hex[:12]}"
        self.connection.execute(
            """
            INSERT INTO graph_edges (
                edge_id, session_id, source_node_id, target_node_id,
                relationship, properties_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge_id,
                session_id,
                source_node_id,
                target_node_id,
                relationship,
                self._json(properties or {}),
                self._now(),
            ),
        )
        return edge_id

    def list_nodes(self, session_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        """List graph nodes."""

        if kind:
            rows = self.connection.query_all(
                """
                SELECT * FROM graph_nodes
                WHERE session_id = ? AND kind = ?
                ORDER BY name ASC
                """,
                (session_id, kind),
            )
        else:
            rows = self.connection.query_all(
                """
                SELECT * FROM graph_nodes
                WHERE session_id = ?
                ORDER BY name ASC
                """,
                (session_id,),
            )
        return [self._decode_row(row) for row in rows]

    def list_edges(
        self,
        session_id: str,
        relationship: str | None = None,
    ) -> list[dict[str, Any]]:
        """List graph edges with source and target node names."""

        query = """
            SELECT
                ge.*,
                source.name AS source_name,
                source.kind AS source_kind,
                target.name AS target_name,
                target.kind AS target_kind
            FROM graph_edges ge
            JOIN graph_nodes source ON source.node_id = ge.source_node_id
            JOIN graph_nodes target ON target.node_id = ge.target_node_id
            WHERE ge.session_id = ?
        """
        params: list[Any] = [session_id]

        if relationship:
            query += " AND ge.relationship = ?"
            params.append(relationship)

        query += " ORDER BY ge.created_at ASC"

        rows = self.connection.query_all(query, tuple(params))
        return [self._decode_row(row) for row in rows]

    def save_attack_path(
        self,
        session_id: str,
        source: str,
        target: str,
        edges: list[dict[str, Any]] | list[Any],
        risk_score: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Persist attack path and return path ID."""

        if not source:
            raise ValueError("source cannot be empty.")
        if not target:
            raise ValueError("target cannot be empty.")

        path_id = f"path_{uuid4().hex[:12]}"
        path_length = len(edges or [])

        self.connection.execute(
            """
            INSERT INTO attack_paths (
                path_id, session_id, source, target, path_length, edges_json,
                risk_score, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                path_id,
                session_id,
                source,
                target,
                path_length,
                self._json(edges or []),
                risk_score,
                self._json(metadata or {}),
                self._now(),
            ),
        )
        return path_id

    def list_attack_paths(
        self,
        session_id: str,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """List attack paths."""

        if target:
            rows = self.connection.query_all(
                """
                SELECT * FROM attack_paths
                WHERE session_id = ? AND target = ?
                ORDER BY risk_score DESC, path_length ASC, created_at ASC
                """,
                (session_id, target),
            )
        else:
            rows = self.connection.query_all(
                """
                SELECT * FROM attack_paths
                WHERE session_id = ?
                ORDER BY risk_score DESC, path_length ASC, created_at ASC
                """,
                (session_id,),
            )

        return [self._decode_row(row) for row in rows]

    def save_from_observation(self, session_id: str, observation: Any) -> str | None:
        """Persist graph data from a BloodHound-style parsed observation."""

        kind = self._get_attr(observation, "kind")
        data = self._get_attr(observation, "data", {}) or {}

        if kind == "ad_relationship":
            return self.upsert_edge(
                session_id=session_id,
                source=str(data.get("source") or ""),
                target=str(data.get("target") or ""),
                relationship=str(data.get("relationship") or ""),
                properties=data,
            )

        if kind == "ad_path":
            return self.save_attack_path(
                session_id=session_id,
                source=str(data.get("source") or ""),
                target=str(data.get("target") or ""),
                edges=data.get("edges") or [],
                metadata=self._get_attr(observation, "metadata", {}) or {},
            )

        if kind == "ad_entity":
            return self.upsert_node(
                session_id=session_id,
                name=str(data.get("name") or ""),
                kind=str(data.get("entity_type") or "unknown"),
                properties=data,
            )

        return None

    @staticmethod
    def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
        """Get attribute or dict key."""

        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

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
