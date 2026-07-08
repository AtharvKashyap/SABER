"""Tests for FindingStore."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from saber.agents.base_agent import AgentObservation
from saber.parsers.base import ParsedFinding, ParsedObservation, ParserSeverity
from saber.reporting.json_exporter import ReportFinding, ReportObservation, ReportSeverity
from saber.storage.finding_store import FindingStore


class FakeConnection:
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
        """Create finding schema."""

        self.conn.executescript(
            """
            CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                step_id TEXT,
                evidence_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_tool TEXT,
                status TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                references_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(session_id, fingerprint)
            );

            CREATE TABLE observations (
                observation_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                step_id TEXT,
                evidence_id TEXT,
                kind TEXT NOT NULL,
                summary TEXT NOT NULL,
                source_tool TEXT,
                data_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@pytest.fixture
def store() -> FindingStore:
    """Create finding store."""

    return FindingStore(FakeConnection())


def parsed_finding() -> ParsedFinding:
    """Create parsed finding."""

    return ParsedFinding(
        title="Critical Nuclei Finding",
        severity=ParserSeverity.CRITICAL,
        description="A critical issue was matched.",
        source_tool="nuclei",
        evidence={"template_id": "cve-1", "matched_at": "https://example.com"},
        references=["https://example.com/ref"],
        metadata={"tag": "cve"},
    )


class TestFindingStore:
    """Validate FindingStore."""

    def test_save_parsed_finding(self, store: FindingStore) -> None:
        """ParsedFinding should save."""

        finding_id = store.save_finding(
            session_id="session_1",
            finding=parsed_finding(),
            step_id="step_1",
            evidence_id="evidence_1",
        )

        finding = store.get_finding(finding_id)

        assert finding_id.startswith("finding_")
        assert finding is not None
        assert finding["title"] == "Critical Nuclei Finding"
        assert finding["severity"] == "critical"
        assert finding["description"] == "A critical issue was matched."
        assert finding["source_tool"] == "nuclei"
        assert finding["status"] == "new"
        assert finding["step_id"] == "step_1"
        assert finding["evidence_id"] == "evidence_1"
        assert finding["evidence"]["template_id"] == "cve-1"
        assert finding["references"] == ["https://example.com/ref"]
        assert finding["metadata"] == {"tag": "cve"}

    def test_save_report_finding(self, store: FindingStore) -> None:
        """ReportFinding should save."""

        report_finding = ReportFinding(
            title="High Report Finding",
            severity=ReportSeverity.HIGH,
            description="High report issue.",
            source_tool="bloodhound",
            evidence={"target": "Domain Admins"},
            references=[],
            metadata={"finding_type": "ad"},
        )

        finding_id = store.save_finding("session_1", report_finding)
        finding = store.get_finding(finding_id)

        assert finding["title"] == "High Report Finding"
        assert finding["severity"] == "high"
        assert finding["source_tool"] == "bloodhound"
        assert finding["metadata"] == {"finding_type": "ad"}

    def test_save_dict_finding(self, store: FindingStore) -> None:
        """Dict finding should save."""

        finding_id = store.save_finding(
            "session_1",
            {
                "title": "Dict Finding",
                "severity": "med",
                "description": "Dict description.",
                "source_tool": "nuclei",
                "evidence": {"host": "example.com"},
                "references": "https://example.com",
            },
        )

        finding = store.get_finding(finding_id)

        assert finding["severity"] == "medium"
        assert finding["references"] == ["https://example.com"]

    def test_invalid_status_raises(self, store: FindingStore) -> None:
        """Invalid status should raise."""

        with pytest.raises(ValueError, match="Invalid finding status"):
            store.save_finding("session_1", parsed_finding(), status="bad")

    def test_duplicate_finding_returns_existing_id(self, store: FindingStore) -> None:
        """Duplicate finding should return existing ID."""

        first = store.save_finding("session_1", parsed_finding())
        second = store.save_finding("session_1", parsed_finding())

        assert second == first
        assert len(store.list_findings("session_1")) == 1

    def test_same_finding_different_session_is_distinct(self, store: FindingStore) -> None:
        """Finding fingerprint includes session ID."""

        first = store.save_finding("session_1", parsed_finding())
        second = store.save_finding("session_2", parsed_finding())

        assert second != first
        assert len(store.list_findings("session_1")) == 1
        assert len(store.list_findings("session_2")) == 1

    def test_list_findings_sorted_by_severity(self, store: FindingStore) -> None:
        """Findings should sort by severity."""

        store.save_finding(
            "session_1",
            {"title": "Low", "severity": "low", "description": "Low.", "source_tool": "tool"},
        )
        store.save_finding(
            "session_1",
            {"title": "Critical", "severity": "critical", "description": "Critical.", "source_tool": "tool"},
        )
        store.save_finding(
            "session_1",
            {"title": "Medium", "severity": "medium", "description": "Medium.", "source_tool": "tool"},
        )

        findings = store.list_findings("session_1")

        assert [finding["title"] for finding in findings] == ["Critical", "Medium", "Low"]

    def test_list_findings_filters(self, store: FindingStore) -> None:
        """Findings should filter by severity and status."""

        first = store.save_finding(
            "session_1",
            {"title": "High", "severity": "high", "description": "High.", "source_tool": "tool"},
        )
        store.save_finding(
            "session_1",
            {"title": "Low", "severity": "low", "description": "Low.", "source_tool": "tool"},
        )
        store.update_finding_status(first, "confirmed")

        high = store.list_findings("session_1", severity="high")
        confirmed = store.list_findings("session_1", status="confirmed")

        assert len(high) == 1
        assert high[0]["title"] == "High"
        assert len(confirmed) == 1
        assert confirmed[0]["status"] == "confirmed"

    def test_update_finding_status_merges_metadata(self, store: FindingStore) -> None:
        """Finding status update should merge metadata."""

        finding_id = store.save_finding(
            "session_1",
            {
                "title": "Finding",
                "severity": "high",
                "description": "Description.",
                "source_tool": "tool",
                "metadata": {"old": True},
            },
        )

        store.update_finding_status(finding_id, "accepted_risk", {"new": True})

        finding = store.get_finding(finding_id)
        assert finding["status"] == "accepted_risk"
        assert finding["metadata"] == {"old": True, "new": True}

    def test_update_missing_finding_raises(self, store: FindingStore) -> None:
        """Updating missing finding should raise."""

        with pytest.raises(KeyError, match="Finding not found"):
            store.update_finding_status("missing", "confirmed")

    def test_update_invalid_status_raises(self, store: FindingStore) -> None:
        """Invalid status update should raise."""

        finding_id = store.save_finding("session_1", parsed_finding())

        with pytest.raises(ValueError, match="Invalid finding status"):
            store.update_finding_status(finding_id, "bad")

    def test_deduplicate_findings_empty_after_insert_dedup(self, store: FindingStore) -> None:
        """Duplicate audit should be empty because insert dedupes."""

        store.save_finding("session_1", parsed_finding())
        store.save_finding("session_1", parsed_finding())

        assert store.deduplicate_findings("session_1") == []

    def test_save_parsed_observation(self, store: FindingStore) -> None:
        """ParsedObservation should save."""

        observation = ParsedObservation(
            kind="service",
            summary="Port 443 open.",
            source_tool="nmap",
            data={"port": 443},
            metadata={"format": "xml"},
        )

        observation_id = store.save_observation(
            "session_1",
            observation,
            step_id="step_1",
            evidence_id="evidence_1",
        )

        saved = store.get_observation(observation_id)
        assert observation_id.startswith("observation_")
        assert saved["kind"] == "service"
        assert saved["summary"] == "Port 443 open."
        assert saved["source_tool"] == "nmap"
        assert saved["step_id"] == "step_1"
        assert saved["evidence_id"] == "evidence_1"
        assert saved["data"] == {"port": 443}
        assert saved["metadata"] == {"format": "xml"}

    def test_save_report_observation(self, store: FindingStore) -> None:
        """ReportObservation should save."""

        observation = ReportObservation(
            kind="web_technology",
            summary="Uses nginx.",
            source_tool="whatweb",
            data={"server": "nginx"},
            metadata={},
        )

        observation_id = store.save_observation("session_1", observation)
        saved = store.get_observation(observation_id)

        assert saved["kind"] == "web_technology"
        assert saved["source_tool"] == "whatweb"
        assert saved["data"] == {"server": "nginx"}

    def test_save_agent_observation(self, store: FindingStore) -> None:
        """AgentObservation should save."""

        observation = AgentObservation(
            summary="Agent saw web surface.",
            tool_name="whatweb",
            action="fingerprint",
            success=True,
            metadata={"agent": "web_agent"},
        )

        observation_id = store.save_observation("session_1", observation)
        saved = store.get_observation(observation_id)

        assert saved["kind"] == "generic"
        assert saved["summary"] == "Agent saw web surface."
        assert saved["source_tool"] == "whatweb"
        assert saved["metadata"] == {"agent": "web_agent"}

    def test_save_dict_observation_and_filters(self, store: FindingStore) -> None:
        """Dict observations should save and filter."""

        store.save_observation(
            "session_1",
            {
                "kind": "service",
                "summary": "Port 80 open.",
                "tool_name": "nmap",
                "data": {"port": 80},
            },
        )
        store.save_observation(
            "session_1",
            {
                "kind": "web_technology",
                "summary": "Uses nginx.",
                "source_tool": "whatweb",
            },
        )

        service = store.list_observations("session_1", kind="service")
        whatweb = store.list_observations("session_1", source_tool="whatweb")

        assert len(service) == 1
        assert service[0]["source_tool"] == "nmap"
        assert len(whatweb) == 1
        assert whatweb[0]["kind"] == "web_technology"
