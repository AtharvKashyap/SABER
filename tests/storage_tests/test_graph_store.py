"""Tests for GraphStore."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from saber.parsers.base import ParsedObservation
from saber.storage.graph_store import GraphStore


class TestConnection:
    """Small sqlite test connection with the store interface."""

    def __init__(self) -> None:
        """Initialize in-memory sqlite DB."""

        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
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

    def _create_schema(self) -> None:
        """Create graph schema."""

        self.conn.executescript(
            """
            CREATE TABLE graph_nodes (
                node_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(session_id, name, kind)
            );

            CREATE TABLE graph_edges (
                edge_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(session_id, source_node_id, target_node_id, relationship)
            );

            CREATE TABLE attack_paths (
                path_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                path_length INTEGER NOT NULL,
                edges_json TEXT NOT NULL,
                risk_score REAL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@pytest.fixture
def store() -> GraphStore:
    """Create graph store."""

    return GraphStore(TestConnection())


class TestGraphStore:
    """Validate GraphStore."""

    def test_upsert_node_creates_node(self, store: GraphStore) -> None:
        """Node should save."""

        node_id = store.upsert_node(
            session_id="session_1",
            name="alice",
            kind="user",
            labels=["User"],
            properties={"enabled": True},
        )

        nodes = store.list_nodes("session_1")

        assert node_id.startswith("node_")
        assert len(nodes) == 1
        assert nodes[0]["name"] == "alice"
        assert nodes[0]["kind"] == "user"
        assert nodes[0]["labels"] == ["User"]
        assert nodes[0]["properties"] == {"enabled": True}

    def test_upsert_node_validates_name(self, store: GraphStore) -> None:
        """Empty node name should raise."""

        with pytest.raises(ValueError, match="node name cannot be empty"):
            store.upsert_node("session_1", "")

    def test_upsert_same_node_returns_same_id_and_updates_properties(self, store: GraphStore) -> None:
        """Upserting same node should update and return same ID."""

        first = store.upsert_node("session_1", "alice", kind="user", properties={"old": True})
        second = store.upsert_node("session_1", "alice", kind="user", properties={"new": True})

        nodes = store.list_nodes("session_1", kind="user")

        assert second == first
        assert len(nodes) == 1
        assert nodes[0]["properties"] == {"new": True}

    def test_same_node_name_different_kind_is_distinct(self, store: GraphStore) -> None:
        """Same name with different kind should be separate."""

        user_id = store.upsert_node("session_1", "alice", kind="user")
        group_id = store.upsert_node("session_1", "alice", kind="group")

        assert user_id != group_id
        assert len(store.list_nodes("session_1")) == 2

    def test_upsert_edge_creates_nodes_and_edge(self, store: GraphStore) -> None:
        """Edge should save and create endpoint nodes."""

        edge_id = store.upsert_edge(
            session_id="session_1",
            source="alice",
            target="Helpdesk",
            relationship="MemberOf",
            properties={"raw": "edge"},
            source_kind="user",
            target_kind="group",
        )

        nodes = store.list_nodes("session_1")
        edges = store.list_edges("session_1")

        assert edge_id.startswith("edge_")
        assert len(nodes) == 2
        assert len(edges) == 1
        assert edges[0]["source_name"] == "alice"
        assert edges[0]["source_kind"] == "user"
        assert edges[0]["target_name"] == "Helpdesk"
        assert edges[0]["target_kind"] == "group"
        assert edges[0]["relationship"] == "MemberOf"
        assert edges[0]["properties"] == {"raw": "edge"}

    def test_upsert_edge_validates_required_fields(self, store: GraphStore) -> None:
        """Edge should validate required fields."""

        with pytest.raises(ValueError, match="source cannot be empty"):
            store.upsert_edge("session_1", "", "target", "Rel")

        with pytest.raises(ValueError, match="target cannot be empty"):
            store.upsert_edge("session_1", "source", "", "Rel")

        with pytest.raises(ValueError, match="relationship cannot be empty"):
            store.upsert_edge("session_1", "source", "target", "")

    def test_upsert_same_edge_returns_same_id_and_updates_properties(self, store: GraphStore) -> None:
        """Duplicate edge should update properties and return same ID."""

        first = store.upsert_edge("session_1", "alice", "Helpdesk", "MemberOf", {"old": True})
        second = store.upsert_edge("session_1", "alice", "Helpdesk", "MemberOf", {"new": True})

        edges = store.list_edges("session_1")

        assert second == first
        assert len(edges) == 1
        assert edges[0]["properties"] == {"new": True}

    def test_list_edges_filters_relationship(self, store: GraphStore) -> None:
        """Edges should filter by relationship."""

        store.upsert_edge("session_1", "alice", "Helpdesk", "MemberOf")
        store.upsert_edge("session_1", "bob", "DC01", "AdminTo")

        admin_edges = store.list_edges("session_1", relationship="AdminTo")

        assert len(admin_edges) == 1
        assert admin_edges[0]["source_name"] == "bob"
        assert admin_edges[0]["relationship"] == "AdminTo"

    def test_save_and_list_attack_path(self, store: GraphStore) -> None:
        """Attack path should save."""

        path_id = store.save_attack_path(
            session_id="session_1",
            source="alice",
            target="Domain Admins",
            edges=[
                {"source": "alice", "relationship": "MemberOf", "target": "Helpdesk"},
                {"source": "Helpdesk", "relationship": "GenericAll", "target": "Domain Admins"},
            ],
            risk_score=9.5,
            metadata={"source_tool": "bloodhound"},
        )

        paths = store.list_attack_paths("session_1")

        assert path_id.startswith("path_")
        assert len(paths) == 1
        assert paths[0]["source"] == "alice"
        assert paths[0]["target"] == "Domain Admins"
        assert paths[0]["path_length"] == 2
        assert paths[0]["risk_score"] == 9.5
        assert paths[0]["metadata"] == {"source_tool": "bloodhound"}

    def test_save_attack_path_validates_source_and_target(self, store: GraphStore) -> None:
        """Attack path should validate source and target."""

        with pytest.raises(ValueError, match="source cannot be empty"):
            store.save_attack_path("session_1", "", "Domain Admins", [])

        with pytest.raises(ValueError, match="target cannot be empty"):
            store.save_attack_path("session_1", "alice", "", [])

    def test_list_attack_paths_filters_target(self, store: GraphStore) -> None:
        """Attack paths should filter by target."""

        store.save_attack_path("session_1", "alice", "Domain Admins", [], risk_score=9)
        store.save_attack_path("session_1", "bob", "Workstation01", [], risk_score=2)

        paths = store.list_attack_paths("session_1", target="Domain Admins")

        assert len(paths) == 1
        assert paths[0]["source"] == "alice"
        assert paths[0]["target"] == "Domain Admins"

    def test_save_from_relationship_observation(self, store: GraphStore) -> None:
        """AD relationship observation should save as edge."""

        observation = ParsedObservation(
            kind="ad_relationship",
            summary="alice MemberOf Helpdesk.",
            source_tool="bloodhound",
            data={"source": "alice", "relationship": "MemberOf", "target": "Helpdesk"},
            metadata={},
        )

        edge_id = store.save_from_observation("session_1", observation)
        edges = store.list_edges("session_1")

        assert edge_id.startswith("edge_")
        assert len(edges) == 1
        assert edges[0]["source_name"] == "alice"
        assert edges[0]["relationship"] == "MemberOf"

    def test_save_from_path_observation(self, store: GraphStore) -> None:
        """AD path observation should save as attack path."""

        observation = ParsedObservation(
            kind="ad_path",
            summary="Path to Domain Admins.",
            source_tool="bloodhound",
            data={
                "source": "alice",
                "target": "Domain Admins",
                "edges": [{"source": "alice", "target": "Domain Admins"}],
            },
            metadata={"risk": "high"},
        )

        path_id = store.save_from_observation("session_1", observation)
        paths = store.list_attack_paths("session_1")

        assert path_id.startswith("path_")
        assert len(paths) == 1
        assert paths[0]["target"] == "Domain Admins"
        assert paths[0]["metadata"] == {"risk": "high"}

    def test_save_from_entity_observation(self, store: GraphStore) -> None:
        """AD entity observation should save as node."""

        observation = ParsedObservation(
            kind="ad_entity",
            summary="Entity alice.",
            source_tool="bloodhound",
            data={"name": "alice", "entity_type": "user"},
            metadata={},
        )

        node_id = store.save_from_observation("session_1", observation)
        nodes = store.list_nodes("session_1")

        assert node_id.startswith("node_")
        assert len(nodes) == 1
        assert nodes[0]["name"] == "alice"
        assert nodes[0]["kind"] == "user"

    def test_save_from_unsupported_observation_returns_none(self, store: GraphStore) -> None:
        """Unsupported observations should be ignored."""

        observation = ParsedObservation(
            kind="service",
            summary="Port open.",
            source_tool="nmap",
            data={"port": 443},
            metadata={},
        )

        assert store.save_from_observation("session_1", observation) is None
