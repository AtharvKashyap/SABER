"""Tests for EvidenceIndex."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from saber.storage.evidence_index import EvidenceIndex


class TestConnection:
    """Small sqlite test connection with the store interface."""

    def __init__(self) -> None:
        """Initialize in-memory sqlite DB."""

        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self._create_schema()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        """Execute SQL."""

        cursor = self.conn.execute(sql, params)
        self.conn.commit()
        return cursor

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        """Query one row."""

        return self.conn.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        """Query all rows."""

        return list(self.conn.execute(sql, params).fetchall())

    def _create_schema(self) -> None:
        """Create evidence schema."""

        self.conn.executescript(
            """
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                step_id TEXT,
                tool_name TEXT,
                action TEXT,
                title TEXT NOT NULL,
                path TEXT NOT NULL,
                mime_type TEXT,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@pytest.fixture
def store() -> EvidenceIndex:
    """Create evidence index."""

    return EvidenceIndex(TestConnection())


def write_file(path: Path, content: str) -> Path:
    """Write test evidence file."""

    path.write_text(content)
    return path


def sha256_text(content: str) -> str:
    """Hash text content."""

    return hashlib.sha256(content.encode()).hexdigest()


class TestEvidenceIndex:
    """Validate EvidenceIndex."""

    def test_add_and_get_evidence(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Evidence should save with metadata."""

        evidence_file = write_file(tmp_path / "nmap.xml", "<xml>evidence</xml>")

        evidence_id = store.add_evidence(
            session_id="session_1",
            step_id="step_1",
            tool_name="nmap",
            action="service_scan",
            title="Nmap XML Output",
            path=evidence_file,
            metadata={"phase": "recon"},
        )

        evidence = store.get_evidence(evidence_id)

        assert evidence_id.startswith("evidence_")
        assert evidence is not None
        assert evidence["session_id"] == "session_1"
        assert evidence["step_id"] == "step_1"
        assert evidence["tool_name"] == "nmap"
        assert evidence["action"] == "service_scan"
        assert evidence["title"] == "Nmap XML Output"
        assert evidence["path"] == str(evidence_file)
        assert evidence["mime_type"] in {"application/xml", "text/xml"}
        assert evidence["sha256"] == sha256_text("<xml>evidence</xml>")
        assert evidence["size_bytes"] == evidence_file.stat().st_size
        assert evidence["metadata"] == {"phase": "recon"}

    def test_add_evidence_validates_session_id(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Empty session ID should raise."""

        evidence_file = write_file(tmp_path / "evidence.txt", "data")

        with pytest.raises(ValueError, match="session_id cannot be empty"):
            store.add_evidence("", evidence_file, "Evidence")

    def test_add_evidence_validates_title(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Empty title should raise."""

        evidence_file = write_file(tmp_path / "evidence.txt", "data")

        with pytest.raises(ValueError, match="title cannot be empty"):
            store.add_evidence("session_1", evidence_file, "")

    def test_add_missing_file_raises(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Missing file should raise."""

        with pytest.raises(FileNotFoundError, match="Evidence file does not exist"):
            store.add_evidence("session_1", tmp_path / "missing.txt", "Missing")

    def test_add_directory_raises(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Directory path should raise."""

        with pytest.raises(ValueError, match="Evidence path is not a file"):
            store.add_evidence("session_1", tmp_path, "Directory")

    def test_custom_mime_type(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Provided MIME type should be used."""

        evidence_file = write_file(tmp_path / "output.unknown", "data")

        evidence_id = store.add_evidence(
            "session_1",
            evidence_file,
            "Custom MIME",
            mime_type="application/x-saber",
        )

        evidence = store.get_evidence(evidence_id)
        assert evidence["mime_type"] == "application/x-saber"

    def test_list_evidence_by_session(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Evidence should list by session."""

        first = write_file(tmp_path / "one.txt", "one")
        second = write_file(tmp_path / "two.txt", "two")
        third = write_file(tmp_path / "three.txt", "three")

        store.add_evidence("session_1", first, "One")
        store.add_evidence("session_1", second, "Two")
        store.add_evidence("session_2", third, "Three")

        session_one = store.list_evidence("session_1")
        session_two = store.list_evidence("session_2")

        assert [item["title"] for item in session_one] == ["One", "Two"]
        assert [item["title"] for item in session_two] == ["Three"]

    def test_list_step_evidence(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Evidence should list by session and step."""

        first = write_file(tmp_path / "one.txt", "one")
        second = write_file(tmp_path / "two.txt", "two")
        third = write_file(tmp_path / "three.txt", "three")

        store.add_evidence("session_1", first, "One", step_id="step_1")
        store.add_evidence("session_1", second, "Two", step_id="step_2")
        store.add_evidence("session_1", third, "Three", step_id="step_1")

        step_one = store.list_step_evidence("session_1", "step_1")

        assert [item["title"] for item in step_one] == ["One", "Three"]

    def test_verify_evidence_true_for_unchanged_file(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Unchanged evidence should verify."""

        evidence_file = write_file(tmp_path / "evidence.txt", "original")

        evidence_id = store.add_evidence("session_1", evidence_file, "Evidence")

        assert store.verify_evidence(evidence_id) is True

    def test_verify_evidence_false_after_modification(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Modified evidence should fail verification."""

        evidence_file = write_file(tmp_path / "evidence.txt", "original")

        evidence_id = store.add_evidence("session_1", evidence_file, "Evidence")
        evidence_file.write_text("modified")

        assert store.verify_evidence(evidence_id) is False

    def test_verify_evidence_false_after_delete(self, store: EvidenceIndex, tmp_path: Path) -> None:
        """Deleted evidence should fail verification."""

        evidence_file = write_file(tmp_path / "evidence.txt", "original")

        evidence_id = store.add_evidence("session_1", evidence_file, "Evidence")
        evidence_file.unlink()

        assert store.verify_evidence(evidence_id) is False

    def test_verify_missing_evidence_raises(self, store: EvidenceIndex) -> None:
        """Missing evidence row should raise."""

        with pytest.raises(KeyError, match="Evidence not found"):
            store.verify_evidence("missing")

    def test_compute_sha256(self, tmp_path: Path) -> None:
        """compute_sha256 should return expected digest."""

        evidence_file = write_file(tmp_path / "evidence.txt", "hello")

        assert EvidenceIndex.compute_sha256(evidence_file) == hashlib.sha256(b"hello").hexdigest()

    def test_detect_mime_type_known_and_unknown(self, tmp_path: Path) -> None:
        """MIME type detection should guess known files and fallback unknown."""

        txt = tmp_path / "note.txt"
        unknown = tmp_path / "file.nopeunknownextension"
        txt.write_text("hello")
        unknown.write_text("hello")

        assert EvidenceIndex.detect_mime_type(txt) == "text/plain"
        assert EvidenceIndex.detect_mime_type(unknown) == "application/octet-stream"
