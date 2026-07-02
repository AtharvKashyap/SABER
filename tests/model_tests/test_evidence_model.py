

"""Tests for SABER evidence models.

This file verifies that `saber.models.evidence` correctly validates evidence
records, command metadata, sensitivity handling, compact references, and evidence
bundles before these objects are used by EvidenceStore, findings, and reports.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from saber.models.evidence import (
    CommandMetadata,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceSensitivity,
    EvidenceSource,
    EvidenceStatus,
    EvidenceType,
)
from saber.models.target import Target, TargetType

VALID_SHA256 = "a" * 64


def make_target() -> Target:
    """Create a reusable target for evidence tests.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.IP, value="192.168.1.10")


def make_evidence(
    evidence_type: EvidenceType = EvidenceType.TOOL_TEXT,
    title: str = "Nmap service output",
) -> EvidenceRecord:
    """Create a reusable evidence record for tests.

    Args:
        evidence_type: Evidence type to assign.
        title: Evidence title.

    Returns:
        A validated EvidenceRecord object.
    """

    return EvidenceRecord(
        type=evidence_type,
        title=title,
        target=make_target(),
        file_path="evidence/nmap.txt",
        tool_name="nmap",
    )


class TestCommandMetadata:
    """Validate command metadata behavior."""

    def test_valid_command_metadata(self) -> None:
        """Valid command metadata should be accepted."""

        started_at = datetime.now(UTC)
        finished_at = started_at + timedelta(seconds=3)

        metadata = CommandMetadata(
            command=[" nmap ", " -sV ", "", "192.168.1.10"],
            tool="nmap",
            return_code=0,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=3.0,
            sandboxed=True,
            working_directory="/workspace",
        )

        assert metadata.command == ["nmap", "-sV", "192.168.1.10"]
        assert metadata.tool == "nmap"
        assert metadata.return_code == 0
        assert metadata.duration_seconds == 3.0
        assert metadata.sandboxed is True

    def test_command_argument_with_null_byte_raises_error(self) -> None:
        """Command arguments containing null bytes should be rejected."""

        with pytest.raises(ValueError):
            CommandMetadata(command=["nmap", "bad\x00arg"])

    def test_finished_before_started_raises_error(self) -> None:
        """Command metadata should reject reversed timestamps."""

        started_at = datetime.now(UTC)
        finished_at = started_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            CommandMetadata(started_at=started_at, finished_at=finished_at)


class TestEvidenceRecordCreation:
    """Validate basic EvidenceRecord construction and normalization."""

    def test_valid_evidence_record(self) -> None:
        """A normal file-backed evidence record should be valid."""

        record = EvidenceRecord(
            evidence_id=" ev_123 ",
            type=EvidenceType.TOOL_TEXT,
            source=EvidenceSource.TOOL_WRAPPER,
            status=EvidenceStatus.COLLECTED,
            title=" Nmap Output ",
            description=" Raw service scan output ",
            target=make_target(),
            tool_name=" nmap ",
            file_path=" evidence/raw/nmap.txt ",
            mime_type=" text/plain ",
            sha256=VALID_SHA256.upper(),
            size_bytes=128,
            content_preview=" 22/tcp open ssh ",
        )

        assert record.evidence_id == "ev_123"
        assert record.type == EvidenceType.TOOL_TEXT
        assert record.source == EvidenceSource.TOOL_WRAPPER
        assert record.status == EvidenceStatus.COLLECTED
        assert record.title == "Nmap Output"
        assert record.description == "Raw service scan output"
        assert record.tool_name == "nmap"
        assert record.file_path == "evidence/raw/nmap.txt"
        assert record.mime_type == "text/plain"
        assert record.sha256 == VALID_SHA256
        assert record.size_bytes == 128
        assert record.content_preview == "22/tcp open ssh"
        assert record.target is not None

    def test_auto_generated_evidence_id_has_expected_prefix(self) -> None:
        """Evidence IDs should be auto-generated when omitted."""

        record = make_evidence()

        assert record.evidence_id.startswith("ev_")
        assert len(record.evidence_id) > 3

    def test_empty_optional_text_becomes_none(self) -> None:
        """Optional text fields should normalize empty strings to None."""

        record = EvidenceRecord(
            type=EvidenceType.TOOL_TEXT,
            title="Tool output",
            description="   ",
            tool_name="   ",
            mime_type="   ",
            content_preview="   ",
            file_path="evidence/output.txt",
        )

        assert record.description is None
        assert record.tool_name is None
        assert record.mime_type is None
        assert record.content_preview is None

    def test_file_path_is_normalized_to_posix(self) -> None:
        """Evidence paths should be normalized to POSIX-style strings."""

        record = EvidenceRecord(
            type=EvidenceType.FILE,
            title="Artifact",
            file_path="evidence/raw/output.txt",
        )

        assert record.file_path == "evidence/raw/output.txt"


class TestEvidenceRecordValidation:
    """Validate evidence error handling."""

    @pytest.mark.parametrize("evidence_id", ["", "   ", "ev 123"])
    def test_invalid_evidence_id_raises_error(self, evidence_id: str) -> None:
        """Empty or whitespace-containing evidence IDs should be rejected."""

        with pytest.raises(ValueError):
            EvidenceRecord(
                evidence_id=evidence_id,
                type=EvidenceType.FILE,
                title="Artifact",
                file_path="evidence/file.txt",
            )

    def test_file_path_with_null_byte_raises_error(self) -> None:
        """File paths containing null bytes should be rejected."""

        with pytest.raises(ValueError):
            EvidenceRecord(
                type=EvidenceType.FILE,
                title="Artifact",
                file_path="evidence/evil\x00file.txt",
            )

    @pytest.mark.parametrize("sha256", ["abc", "g" * 64, "a" * 63, "a" * 65])
    def test_invalid_sha256_raises_error(self, sha256: str) -> None:
        """Malformed SHA-256 values should be rejected."""

        with pytest.raises(ValueError):
            EvidenceRecord(
                type=EvidenceType.FILE,
                title="Artifact",
                file_path="evidence/file.txt",
                sha256=sha256,
            )

    @pytest.mark.parametrize(
        "evidence_type",
        [EvidenceType.COMMAND_OUTPUT, EvidenceType.TOOL_JSON, EvidenceType.TOOL_XML],
    )
    def test_tool_evidence_requires_content_or_file_or_parsed_data(
        self,
        evidence_type: EvidenceType,
    ) -> None:
        """Tool evidence should require some raw or parsed content reference."""

        with pytest.raises(ValueError):
            EvidenceRecord(
                type=evidence_type,
                title="Tool evidence",
            )

    def test_secret_evidence_with_preview_must_be_redacted(self) -> None:
        """Secret evidence with preview content must be explicitly redacted."""

        with pytest.raises(ValueError):
            EvidenceRecord(
                type=EvidenceType.TOOL_TEXT,
                title="Secret output",
                content_preview="password=secret",
                sensitivity=EvidenceSensitivity.SECRET,
                redacted=False,
            )

    def test_secret_evidence_with_redacted_preview_is_allowed(self) -> None:
        """Secret evidence should be allowed when the preview is redacted."""

        record = EvidenceRecord(
            type=EvidenceType.TOOL_TEXT,
            title="Secret output",
            content_preview="password=<redacted>",
            sensitivity=EvidenceSensitivity.SECRET,
            redacted=True,
        )

        assert record.sensitivity == EvidenceSensitivity.SECRET
        assert record.redacted is True


class TestEvidenceRecordHelpers:
    """Validate EvidenceRecord helper properties and copy methods."""

    def test_has_file_property(self) -> None:
        """has_file should reflect whether file_path exists."""

        with_file = make_evidence()
        without_file = EvidenceRecord(
            type=EvidenceType.ANALYST_NOTE,
            title="Analyst note",
            content_preview="Observed exposed SSH service.",
        )

        assert with_file.has_file
        assert not without_file.has_file

    def test_is_sensitive_property(self) -> None:
        """Only confidential and secret evidence should be sensitive."""

        public = make_evidence().model_copy(update={"sensitivity": EvidenceSensitivity.PUBLIC})
        internal = make_evidence().model_copy(update={"sensitivity": EvidenceSensitivity.INTERNAL})
        confidential = make_evidence().model_copy(
            update={"sensitivity": EvidenceSensitivity.CONFIDENTIAL}
        )
        secret = make_evidence().model_copy(
            update={"sensitivity": EvidenceSensitivity.SECRET, "redacted": True}
        )

        assert not public.is_sensitive
        assert not internal.is_sensitive
        assert confidential.is_sensitive
        assert secret.is_sensitive

    def test_status_marker_methods_return_updated_copies(self) -> None:
        """Status helpers should return copied evidence records with updated status."""

        record = make_evidence()

        parsed = record.mark_parsed()
        verified = record.mark_verified()
        rejected = record.mark_rejected()

        assert record.status == EvidenceStatus.COLLECTED
        assert parsed.status == EvidenceStatus.PARSED
        assert verified.status == EvidenceStatus.VERIFIED
        assert rejected.status == EvidenceStatus.REJECTED
        assert verified.can_support_verified_finding
        assert not record.can_support_verified_finding

    def test_sensitivity_and_redaction_marker_methods(self) -> None:
        """Sensitivity helpers should return copied evidence records with updates."""

        record = make_evidence()

        sensitive = record.mark_sensitive(EvidenceSensitivity.CONFIDENTIAL)
        redacted = record.mark_redacted()

        assert record.sensitivity == EvidenceSensitivity.INTERNAL
        assert sensitive.sensitivity == EvidenceSensitivity.CONFIDENTIAL
        assert redacted.redacted is True

    def test_to_reference_returns_compact_reference(self) -> None:
        """Evidence references should include compact report-safe fields."""

        record = EvidenceRecord(
            evidence_id="ev_ref",
            type=EvidenceType.SCREENSHOT,
            title="Login page screenshot",
            file_path="evidence/screens/login.png",
            sensitivity=EvidenceSensitivity.CONFIDENTIAL,
            redacted=True,
            status=EvidenceStatus.VERIFIED,
        )

        assert record.to_reference() == {
            "evidence_id": "ev_ref",
            "type": "screenshot",
            "title": "Login page screenshot",
            "file_path": "evidence/screens/login.png",
            "sensitive": True,
            "redacted": True,
            "status": "verified",
        }

    def test_to_agent_dict_hides_sensitive_preview(self) -> None:
        """Agent handoff data should not include sensitive content previews."""

        record = EvidenceRecord(
            evidence_id="ev_secret",
            type=EvidenceType.TOOL_TEXT,
            title="Credential material",
            target=make_target(),
            tool_name="mimikatz",
            file_path="evidence/secret.txt",
            content_preview="secret=<redacted>",
            sensitivity=EvidenceSensitivity.SECRET,
            redacted=True,
        )

        agent_dict = record.to_agent_dict()

        assert agent_dict["evidence_id"] == "ev_secret"
        assert agent_dict["type"] == "tool_text"
        assert agent_dict["source"] == "tool_wrapper"
        assert agent_dict["status"] == "collected"
        assert agent_dict["title"] == "Credential material"
        assert agent_dict["target"] == {"type": "ip", "value": "192.168.1.10"}
        assert agent_dict["tool_name"] == "mimikatz"
        assert agent_dict["file_path"] == "evidence/secret.txt"
        assert agent_dict["content_preview"] is None
        assert agent_dict["sensitivity"] == "secret"
        assert agent_dict["redacted"] is True

    def test_to_agent_dict_includes_non_sensitive_preview(self) -> None:
        """Agent handoff data may include non-sensitive content previews."""

        record = EvidenceRecord(
            type=EvidenceType.TOOL_TEXT,
            title="Nmap output",
            content_preview="22/tcp open ssh",
            sensitivity=EvidenceSensitivity.INTERNAL,
        )

        assert record.to_agent_dict()["content_preview"] == "22/tcp open ssh"


class TestEvidenceBundle:
    """Validate EvidenceBundle behavior."""

    def test_valid_bundle_creation(self) -> None:
        """Evidence bundles should group records."""

        record = make_evidence().mark_verified()
        bundle = EvidenceBundle(bundle_id=" bundle_1 ", title="Finding evidence", records=[record])

        assert bundle.bundle_id == "bundle_1"
        assert bundle.title == "Finding evidence"
        assert bundle.records == [record]
        assert bundle.created_at.tzinfo == UTC

    @pytest.mark.parametrize("bundle_id", ["", "   ", "bundle 1"])
    def test_invalid_bundle_id_raises_error(self, bundle_id: str) -> None:
        """Invalid bundle IDs should be rejected."""

        with pytest.raises(ValueError):
            EvidenceBundle(bundle_id=bundle_id, title="Bundle")

    def test_verified_records_property(self) -> None:
        """verified_records should return only verified records."""

        collected = make_evidence(title="Collected")
        verified = make_evidence(title="Verified").mark_verified()
        bundle = EvidenceBundle(title="Bundle", records=[collected, verified])

        assert bundle.verified_records == [verified]

    def test_sensitive_records_property(self) -> None:
        """sensitive_records should return confidential and secret records."""

        normal = make_evidence(title="Normal")
        confidential = make_evidence(title="Confidential").mark_sensitive(
            EvidenceSensitivity.CONFIDENTIAL
        )
        secret = make_evidence(title="Secret").model_copy(
            update={"sensitivity": EvidenceSensitivity.SECRET, "redacted": True}
        )
        bundle = EvidenceBundle(title="Bundle", records=[normal, confidential, secret])

        assert bundle.sensitive_records == [confidential, secret]

    def test_add_record_returns_updated_copy(self) -> None:
        """add_record should return a copied bundle with the new record appended."""

        first = make_evidence(title="First")
        second = make_evidence(title="Second")
        bundle = EvidenceBundle(title="Bundle", records=[first])

        updated = bundle.add_record(second)

        assert bundle.records == [first]
        assert updated.records == [first, second]

    def test_to_reference_list(self) -> None:
        """Bundles should expose compact references for every record."""

        record = EvidenceRecord(
            evidence_id="ev_bundle",
            type=EvidenceType.FILE,
            title="Artifact",
            file_path="evidence/artifact.txt",
        )
        bundle = EvidenceBundle(title="Bundle", records=[record])

        assert bundle.to_reference_list() == [
            {
                "evidence_id": "ev_bundle",
                "type": "file",
                "title": "Artifact",
                "file_path": "evidence/artifact.txt",
                "sensitive": False,
                "redacted": False,
                "status": "collected",
            }
        ]