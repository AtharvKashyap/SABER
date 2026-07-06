

"""Tests for SABER finding models.

This file verifies that `saber.models.finding` correctly validates reportable
security findings, enforces evidence-first verification rules, and exposes
report-safe and agent-safe serialization helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from saber.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType
from saber.models.finding import (
    Finding,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingStatus,
    RemediationStep,
    VerificationStatus,
)
from saber.models.target import Target, TargetType


def make_target(
    target_type: TargetType = TargetType.DOMAIN,
    value: str = "example.com",
) -> Target:
    """Create a reusable target for finding tests.

    Args:
        target_type: Target type to create.
        value: Target value to validate and normalize.

    Returns:
        A validated Target object.
    """

    return Target(type=target_type, value=value)


def make_evidence(
    evidence_id: str = "ev_1",
    status: EvidenceStatus = EvidenceStatus.COLLECTED,
) -> EvidenceRecord:
    """Create a reusable evidence record for finding tests.

    Args:
        evidence_id: Evidence identifier to assign.
        status: Evidence verification status to assign.

    Returns:
        A validated EvidenceRecord object.
    """

    return EvidenceRecord(
        evidence_id=evidence_id,
        type=EvidenceType.TOOL_TEXT,
        title="Nmap output",
        target=make_target(),
        file_path="evidence/nmap.txt",
        status=status,
    )


def make_finding() -> Finding:
    """Create a reusable candidate finding for tests.

    Returns:
        A validated Finding object.
    """

    return Finding(
        finding_id="finding_1",
        title="Exposed SSH service",
        description="SSH is exposed on a reachable host.",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        affected_targets=[make_target()],
        evidence=[make_evidence()],
        tags=["Network", "network", "SSH"],
    )


class TestRemediationStep:
    """Validate remediation step behavior."""

    def test_valid_remediation_step(self) -> None:
        """A remediation step with title, description, and priority should be valid."""

        step = RemediationStep(
            title=" Restrict SSH ",
            description=" Limit SSH access to the VPN subnet. ",
            priority=2,
        )

        assert step.title == "Restrict SSH"
        assert step.description == "Limit SSH access to the VPN subnet."
        assert step.priority == 2

    @pytest.mark.parametrize(
        ("title", "description"),
        [("", "Fix it"), ("Restrict SSH", ""), ("   ", "Fix it")],
    )
    def test_empty_remediation_text_raises_error(
        self,
        title: str,
        description: str,
    ) -> None:
        """Empty remediation title or description should be rejected."""

        with pytest.raises(ValueError):
            RemediationStep(title=title, description=description)


class TestFindingReference:
    """Validate finding reference behavior."""

    def test_valid_reference_normalizes_text(self) -> None:
        """Reference text fields should be stripped."""

        reference = FindingReference(
            label=" CVE-2024-0001 ",
            url=" https://example.com/advisory ",
            source=" Vendor ",
        )

        assert reference.label == "CVE-2024-0001"
        assert reference.url == "https://example.com/advisory"
        assert reference.source == "Vendor"

    def test_empty_optional_reference_text_becomes_none(self) -> None:
        """Empty optional reference fields should normalize to None."""

        reference = FindingReference(label="CWE-79", url="   ", source="   ")

        assert reference.url is None
        assert reference.source is None


class TestFindingCreation:
    """Validate basic Finding construction and normalization."""

    def test_valid_candidate_finding(self) -> None:
        """A normal candidate finding should be valid."""

        finding = make_finding()

        assert finding.finding_id == "finding_1"
        assert finding.title == "Exposed SSH service"
        assert finding.description == "SSH is exposed on a reachable host."
        assert finding.severity == FindingSeverity.MEDIUM
        assert finding.confidence == FindingConfidence.HIGH
        assert finding.verification_status == VerificationStatus.CANDIDATE
        assert finding.status == FindingStatus.OPEN
        assert finding.affected_targets[0].value == "example.com"
        assert finding.evidence[0].evidence_id == "ev_1"
        assert finding.tags == ["network", "ssh"]

    def test_auto_generated_finding_id_has_expected_prefix(self) -> None:
        """Finding IDs should be auto-generated when omitted."""

        finding = Finding(
            title="Open port",
            description="A port was observed open.",
        )

        assert finding.finding_id.startswith("finding_")
        assert len(finding.finding_id) > len("finding_")

    def test_text_fields_are_trimmed(self) -> None:
        """Finding text fields should be stripped."""

        finding = Finding(
            finding_id=" finding_trimmed ",
            title=" Open SSH ",
            description=" SSH is reachable. ",
            cvss_vector=" CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N ",
            cvss_score=5.3,
            business_impact=" Increased attack surface. ",
            technical_impact=" Remote service exposure. ",
        )

        assert finding.finding_id == "finding_trimmed"
        assert finding.title == "Open SSH"
        assert finding.description == "SSH is reachable."
        assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        assert finding.business_impact == "Increased attack surface."
        assert finding.technical_impact == "Remote service exposure."

    def test_string_lists_are_normalized_and_deduplicated(self) -> None:
        """CWE IDs, CVE IDs, and tags should be normalized and deduplicated."""

        finding = Finding(
            title="Weak cipher",
            description="Weak TLS cipher was observed.",
            cwe_ids=[" CWE-327 ", "cwe-327", "CWE-326"],
            cve_ids=[" CVE-2024-0001 ", "cve-2024-0001"],
            tags=[" TLS ", "tls", "crypto"],
        )

        assert finding.cwe_ids == ["cwe-327", "cwe-326"]
        assert finding.cve_ids == ["cve-2024-0001"]
        assert finding.tags == ["tls", "crypto"]


class TestFindingValidation:
    """Validate finding consistency rules."""

    @pytest.mark.parametrize("finding_id", ["", "   ", "finding 1"])
    def test_invalid_finding_id_raises_error(self, finding_id: str) -> None:
        """Empty or whitespace-containing finding IDs should be rejected."""

        with pytest.raises(ValueError):
            Finding(
                finding_id=finding_id,
                title="Open SSH",
                description="SSH is reachable.",
            )

    def test_last_seen_before_first_seen_raises_error(self) -> None:
        """Finding timestamps should be chronological."""

        first_seen = datetime.now(UTC)
        last_seen = first_seen - timedelta(seconds=1)

        with pytest.raises(ValueError):
            Finding(
                title="Open SSH",
                description="SSH is reachable.",
                first_seen=first_seen,
                last_seen=last_seen,
            )

    def test_cvss_vector_requires_cvss_score(self) -> None:
        """A CVSS vector should not be accepted without a CVSS score."""

        with pytest.raises(ValueError):
            Finding(
                title="Open SSH",
                description="SSH is reachable.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            )

    def test_verified_finding_requires_affected_target(self) -> None:
        """Verified findings should require at least one affected target."""

        with pytest.raises(ValueError):
            Finding(
                title="Open SSH",
                description="SSH is reachable.",
                verification_status=VerificationStatus.VERIFIED,
                evidence=[make_evidence(status=EvidenceStatus.VERIFIED)],
            )

    def test_verified_finding_requires_verified_evidence(self) -> None:
        """Verified findings should require at least one verified evidence record."""

        with pytest.raises(ValueError):
            Finding(
                title="Open SSH",
                description="SSH is reachable.",
                verification_status=VerificationStatus.VERIFIED,
                affected_targets=[make_target()],
                evidence=[make_evidence(status=EvidenceStatus.COLLECTED)],
            )

    def test_verified_finding_with_verified_evidence_is_valid(self) -> None:
        """Verified findings should be valid when backed by verified evidence."""

        finding = Finding(
            title="Open SSH",
            description="SSH is reachable.",
            verification_status=VerificationStatus.VERIFIED,
            affected_targets=[make_target()],
            evidence=[make_evidence(status=EvidenceStatus.VERIFIED)],
        )

        assert finding.is_verified
        assert len(finding.verified_evidence) == 1


class TestFindingHelpers:
    """Validate finding helper properties and copy methods."""

    def test_verified_evidence_property(self) -> None:
        """verified_evidence should return only verified evidence records."""

        collected = make_evidence(evidence_id="ev_collected")
        verified = make_evidence(evidence_id="ev_verified", status=EvidenceStatus.VERIFIED)
        finding = make_finding().model_copy(update={"evidence": [collected, verified]})

        assert finding.verified_evidence == [verified]

    def test_is_reportable_property(self) -> None:
        """Only verified, non-closed findings should be reportable."""

        verified = Finding(
            title="Open SSH",
            description="SSH is reachable.",
            verification_status=VerificationStatus.VERIFIED,
            status=FindingStatus.OPEN,
            affected_targets=[make_target()],
            evidence=[make_evidence(status=EvidenceStatus.VERIFIED)],
        )
        closed = verified.model_copy(update={"status": FindingStatus.CLOSED})
        candidate = make_finding()

        assert verified.is_reportable
        assert not closed.is_reportable
        assert not candidate.is_reportable

    def test_has_sensitive_evidence_property(self) -> None:
        """Findings should identify whether linked evidence is sensitive."""

        normal = make_evidence(evidence_id="ev_normal")
        sensitive = make_evidence(evidence_id="ev_sensitive").mark_sensitive()
        finding = make_finding().model_copy(update={"evidence": [normal, sensitive]})

        assert finding.has_sensitive_evidence

    def test_add_evidence_returns_updated_copy(self) -> None:
        """add_evidence should append evidence without mutating the original."""

        finding = make_finding()
        new_evidence = make_evidence(evidence_id="ev_2")

        updated = finding.add_evidence(new_evidence)

        assert len(finding.evidence) == 1
        assert finding.evidence[0].evidence_id == "ev_1"
        assert len(updated.evidence) == 2
        assert updated.evidence[0].evidence_id == "ev_1"
        assert updated.evidence[1].evidence_id == "ev_2"

    def test_add_target_returns_updated_copy(self) -> None:
        """add_target should append a new target without mutating the original."""

        finding = make_finding()
        new_target = make_target(TargetType.URL, "https://example.com/login")

        updated = finding.add_target(new_target)

        assert finding.affected_targets == [make_target()]
        assert updated.affected_targets == [make_target(), new_target]

    def test_add_duplicate_target_returns_same_targets(self) -> None:
        """add_target should avoid duplicate target entries."""

        finding = make_finding()
        updated = finding.add_target(make_target())

        assert updated.affected_targets == [make_target()]

    def test_marker_methods_return_updated_copies(self) -> None:
        """Finding marker methods should return copied findings with updated state."""

        finding = make_finding()

        verified = finding.mark_verified()
        unverified = finding.mark_unverified()
        false_positive = finding.mark_false_positive()

        assert finding.verification_status == VerificationStatus.CANDIDATE
        assert verified.verification_status == VerificationStatus.VERIFIED
        assert unverified.verification_status == VerificationStatus.UNVERIFIED
        assert false_positive.verification_status == VerificationStatus.FALSE_POSITIVE
        assert false_positive.status == FindingStatus.CLOSED

    @pytest.mark.parametrize(
        ("severity", "rank"),
        [
            (FindingSeverity.INFO, 0),
            (FindingSeverity.LOW, 1),
            (FindingSeverity.MEDIUM, 2),
            (FindingSeverity.HIGH, 3),
            (FindingSeverity.CRITICAL, 4),
        ],
    )
    def test_severity_rank(self, severity: FindingSeverity, rank: int) -> None:
        """severity_rank should support deterministic sorting."""

        finding = make_finding().model_copy(update={"severity": severity})

        assert finding.severity_rank() == rank


class TestFindingSerialization:
    """Validate report-safe and agent-safe finding serialization."""

    def test_to_report_dict(self) -> None:
        """to_report_dict should return report-safe structured finding data."""

        finding = Finding(
            finding_id="finding_report",
            title="Open SSH",
            description="SSH is reachable.",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.VERIFIED,
            status=FindingStatus.OPEN,
            affected_targets=[make_target()],
            evidence=[make_evidence(status=EvidenceStatus.VERIFIED)],
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_ids=["CWE-200"],
            cve_ids=["CVE-2024-0001"],
            business_impact="Increased attack surface.",
            technical_impact="Remote service exposure.",
            remediation=[
                RemediationStep(
                    title="Restrict SSH",
                    description="Limit SSH to trusted networks.",
                    priority=2,
                ),
                RemediationStep(
                    title="Enable MFA",
                    description="Require MFA for remote access.",
                    priority=1,
                ),
            ],
            references=[FindingReference(label="CWE-200", source="MITRE")],
            tags=["ssh"],
        )

        report = finding.to_report_dict()

        assert report["finding_id"] == "finding_report"
        assert report["title"] == "Open SSH"
        assert report["severity"] == "medium"
        assert report["confidence"] == "high"
        assert report["verification_status"] == "verified"
        assert report["status"] == "open"
        assert report["affected_targets"] == [{"type": "domain", "value": "example.com"}]
        assert report["evidence"][0]["evidence_id"] == "ev_1"
        assert report["cvss_score"] == 5.3
        assert report["cwe_ids"] == ["cwe-200"]
        assert report["cve_ids"] == ["cve-2024-0001"]
        assert report["business_impact"] == "Increased attack surface."
        assert report["technical_impact"] == "Remote service exposure."
        assert report["remediation"][0]["title"] == "Enable MFA"
        assert report["remediation"][1]["title"] == "Restrict SSH"
        assert report["references"] == [{"label": "CWE-200", "url": None, "source": "MITRE"}]
        assert report["tags"] == ["ssh"]
        assert report["has_sensitive_evidence"] is False
        assert "first_seen" in report
        assert "last_seen" in report

    def test_to_agent_dict(self) -> None:
        """to_agent_dict should return compact finding context for agents."""

        finding = Finding(
            finding_id="finding_agent",
            title="Open SSH",
            description="SSH is reachable.",
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.MEDIUM,
            verification_status=VerificationStatus.CANDIDATE,
            affected_targets=[make_target()],
            evidence=[make_evidence(evidence_id="ev_agent")],
            cvss_score=3.1,
            cwe_ids=["CWE-200"],
            cve_ids=["CVE-2024-0001"],
            tags=["ssh"],
        )

        assert finding.to_agent_dict() == {
            "finding_id": "finding_agent",
            "title": "Open SSH",
            "severity": "low",
            "confidence": "medium",
            "verification_status": "candidate",
            "affected_targets": [{"type": "domain", "value": "example.com"}],
            "evidence_refs": ["ev_agent"],
            "cvss_score": 3.1,
            "cwe_ids": ["cwe-200"],
            "cve_ids": ["cve-2024-0001"],
            "tags": ["ssh"],
        }