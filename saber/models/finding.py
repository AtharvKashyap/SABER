"""Finding models used across SABER.

This file defines the canonical structure for vulnerabilities, exposures,
misconfigurations, and validated security issues discovered during a SABER
mission.

Inputs:
    - Normalized targets from saber.models.target.
    - Evidence records from saber.models.evidence.
    - Agent observations, parser output, and analyst review decisions.

Outputs:
    - Validated Finding objects.
    - Report-safe dictionaries for PDF, XLSX, JSON, and Markdown exporters.
    - Helper methods for adding evidence, marking verification state, and
      deciding whether a finding is reportable.

Used by:
    - saber.core.evidence_store
    - saber.tools.* wrappers
    - saber.agents.reporter
    - saber.storage.database
    - saber.reporting exporters
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from saber.models.evidence import EvidenceRecord, EvidenceStatus
from saber.models.target import Target


class FindingSeverity(StrEnum):
    """Severity levels used for SABER findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(StrEnum):
    """Confidence level for a finding or observation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(StrEnum):
    """Verification state for a finding.

    Values:
        CANDIDATE: Possible finding that still needs evidence review.
        UNVERIFIED: Finding could not be verified with available evidence.
        VERIFIED: Finding is backed by verified evidence.
        FALSE_POSITIVE: Reviewed and determined not to be valid.
        ACCEPTED_RISK: Valid finding accepted by owner/client.
    """

    CANDIDATE = "candidate"
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FindingStatus(StrEnum):
    """Lifecycle state for a finding."""

    OPEN = "open"
    IN_REVIEW = "in_review"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    CLOSED = "closed"


class RemediationStep(BaseModel):
    """One remediation action for a finding.

    Args:
        title: Short remediation step title.
        description: Detailed remediation guidance.
        priority: Order or urgency of this remediation step.

    Returns:
        A validated remediation step.
    """

    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    priority: int = Field(default=1, ge=1)

    @field_validator("title", "description")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        """Normalize remediation text fields.

        Args:
            value: Raw text value.

        Returns:
            Stripped text.

        Raises:
            ValueError: If the text is empty.
        """

        normalized = value.strip()
        if not normalized:
            raise ValueError("remediation text cannot be empty")
        return normalized


class FindingReference(BaseModel):
    """External reference for a finding.

    Args:
        label: Reference label, such as CVE ID, CWE ID, or vendor advisory.
        url: Optional URL for the reference.
        source: Optional source name.

    Returns:
        A validated finding reference.
    """

    label: str = Field(..., min_length=1)
    url: str | None = None
    source: str | None = None

    @field_validator("label", "url", "source", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        """Normalize reference text fields.

        Args:
            value: Raw string or None.

        Returns:
            Stripped string, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class Finding(BaseModel):
    """Canonical SABER finding.

    Args:
        finding_id: Stable finding identifier. Auto-generated when omitted.
        title: Short finding title.
        description: Technical finding description.
        severity: Qualitative severity.
        confidence: Confidence in the finding.
        verification_status: Evidence verification state.
        status: Finding lifecycle state.
        affected_targets: Targets affected by the finding.
        evidence: Evidence records supporting the finding.
        cvss_score: Optional CVSS score from 0.0 to 10.0.
        cvss_vector: Optional CVSS vector string.
        cwe_ids: Optional CWE identifiers.
        cve_ids: Optional CVE identifiers.
        business_impact: Business-level impact explanation.
        technical_impact: Technical impact explanation.
        remediation: Remediation steps.
        references: External references.
        tags: Labels used for filtering, reporting, or routing.
        first_seen: UTC timestamp when finding was first observed.
        last_seen: UTC timestamp when finding was last observed.
        metadata: Optional structured context.

    Returns:
        A validated finding object suitable for storage and reporting.
    """

    finding_id: str = Field(default_factory=lambda: f"finding_{uuid4().hex}")
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    verification_status: VerificationStatus = VerificationStatus.CANDIDATE
    status: FindingStatus = FindingStatus.OPEN
    affected_targets: list[Target] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    business_impact: str | None = None
    technical_impact: str | None = None
    remediation: list[RemediationStep] = Field(default_factory=list)
    references: list[FindingReference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, finding_id: str) -> str:
        """Validate and normalize a finding ID.

        Args:
            finding_id: Raw finding identifier.

        Returns:
            Stripped finding identifier.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        normalized = finding_id.strip()
        if not normalized:
            raise ValueError("finding_id cannot be empty")
        if any(character.isspace() for character in normalized):
            raise ValueError("finding_id cannot contain whitespace")
        return normalized

    @field_validator(
        "title",
        "description",
        "cvss_vector",
        "business_impact",
        "technical_impact",
        mode="before",
    )
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        """Normalize finding text fields.

        Args:
            value: Raw string or None.

        Returns:
            Stripped string, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("cwe_ids", "cve_ids", "tags")
    @classmethod
    def normalize_string_list(cls, values: list[str]) -> list[str]:
        """Normalize and de-duplicate string lists.

        Args:
            values: Raw string values.

        Returns:
            Stripped, lowercased, de-duplicated strings.
        """

        seen: set[str] = set()
        normalized_values: list[str] = []

        for value in values:
            normalized = value.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                normalized_values.append(normalized)

        return normalized_values

    @model_validator(mode="after")
    def validate_finding_consistency(self) -> Finding:
        """Validate cross-field finding rules.

        Returns:
            The validated Finding object.

        Raises:
            ValueError: If verified findings lack verified evidence, if timestamps
            are inconsistent, or if reportable fields are missing.
        """

        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot be earlier than first_seen")

        if self.verification_status == VerificationStatus.VERIFIED:
            if not self.affected_targets:
                raise ValueError("verified findings require at least one affected target")
            if not self.verified_evidence:
                raise ValueError("verified findings require at least one verified evidence record")

        if self.cvss_vector and self.cvss_score is None:
            raise ValueError("cvss_vector requires cvss_score")

        return self

    @property
    def verified_evidence(self) -> list[EvidenceRecord]:
        """Return evidence records marked verified.

        Returns:
            Evidence records with status VERIFIED.
        """

        return [record for record in self.evidence if record.status == EvidenceStatus.VERIFIED]

    @property
    def is_verified(self) -> bool:
        """Return whether the finding is verified.

        Returns:
            True when verification_status is VERIFIED.
        """

        return self.verification_status == VerificationStatus.VERIFIED

    @property
    def is_reportable(self) -> bool:
        """Return whether the finding should appear as a verified report finding.

        Returns:
            True when the finding is verified and not closed as false positive.
        """

        return self.is_verified and self.status not in {
            FindingStatus.CLOSED,
            FindingStatus.RISK_ACCEPTED,
        }

    @property
    def has_sensitive_evidence(self) -> bool:
        """Return whether any linked evidence requires sensitive handling.

        Returns:
            True if at least one evidence record is confidential or secret.
        """

        return any(record.is_sensitive for record in self.evidence)

    def add_evidence(self, record: EvidenceRecord) -> Finding:
        """Return a copy of this finding with one additional evidence record.

        Args:
            record: Evidence record to append.

        Returns:
            A new Finding containing the added evidence.
        """

        return self.model_copy(update={"evidence": [*self.evidence, record]})

    def add_target(self, target: Target) -> Finding:
        """Return a copy of this finding with one additional affected target.

        Args:
            target: Target to append.

        Returns:
            A new Finding containing the added target.
        """

        existing = {(item.type, item.value) for item in self.affected_targets}
        if (target.type, target.value) in existing:
            return self
        return self.model_copy(update={"affected_targets": [*self.affected_targets, target]})

    def mark_verified(self) -> Finding:
        """Return a copy of this finding marked verified.

        Returns:
            A new Finding with verification_status set to VERIFIED.
        """

        return self.model_copy(update={"verification_status": VerificationStatus.VERIFIED})

    def mark_unverified(self) -> Finding:
        """Return a copy of this finding marked unverified.

        Returns:
            A new Finding with verification_status set to UNVERIFIED.
        """

        return self.model_copy(update={"verification_status": VerificationStatus.UNVERIFIED})

    def mark_false_positive(self) -> Finding:
        """Return a copy of this finding marked as a false positive.

        Returns:
            A new Finding with verification_status FALSE_POSITIVE and status CLOSED.
        """

        return self.model_copy(
            update={
                "verification_status": VerificationStatus.FALSE_POSITIVE,
                "status": FindingStatus.CLOSED,
            }
        )

    def severity_rank(self) -> int:
        """Return numeric rank for sorting by severity.

        Returns:
            Integer severity rank from 0 to 4.
        """

        return {
            FindingSeverity.INFO: 0,
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }[self.severity]

    def to_report_dict(self) -> dict[str, Any]:
        """Return a report-safe finding dictionary.

        Returns:
            JSON-compatible finding data for PDF, XLSX, JSON, and Markdown reports.
        """

        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "verification_status": self.verification_status.value,
            "status": self.status.value,
            "affected_targets": [target.to_agent_dict() for target in self.affected_targets],
            "evidence": [record.to_reference() for record in self.evidence],
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "business_impact": self.business_impact,
            "technical_impact": self.technical_impact,
            "remediation": [
                step.model_dump(mode="json") for step in sorted (
                    self.remediation, key=lambda item: item.priority
                )
            ],
            "references": [reference.model_dump(mode="json") for reference in self.references],
            "tags": self.tags,
            "has_sensitive_evidence": self.has_sensitive_evidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    def to_agent_dict(self) -> dict[str, Any]:
        """Return compact finding data for agent handoff.

        Returns:
            JSON-compatible finding context using compact targets and evidence references.
        """

        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "verification_status": self.verification_status.value,
            "affected_targets": [target.to_agent_dict() for target in self.affected_targets],
            "evidence_refs": [record.evidence_id for record in self.evidence],
            "cvss_score": self.cvss_score,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
        }