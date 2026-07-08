"""JSON report exporter for SABER."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


class ReportSeverity(StrEnum):
    """Normalized report severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


SEVERITY_ORDER: dict[ReportSeverity, int] = {
    ReportSeverity.CRITICAL: 0,
    ReportSeverity.HIGH: 1,
    ReportSeverity.MEDIUM: 2,
    ReportSeverity.LOW: 3,
    ReportSeverity.INFO: 4,
    ReportSeverity.UNKNOWN: 5,
}


@dataclass(frozen=True)
class ReportObservation:
    """Normalized report observation."""

    kind: str
    summary: str
    source_tool: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate observation."""

        if not self.kind.strip():
            raise ValueError("ReportObservation.kind cannot be empty.")
        if not self.summary.strip():
            raise ValueError("ReportObservation.summary cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible observation."""

        return {
            "kind": self.kind,
            "summary": self.summary,
            "source_tool": self.source_tool,
            "data": self.data,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ReportFinding:
    """Normalized report finding."""

    title: str
    severity: ReportSeverity
    description: str
    source_tool: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate finding."""

        if not self.title.strip():
            raise ValueError("ReportFinding.title cannot be empty.")
        if not self.description.strip():
            raise ValueError("ReportFinding.description cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible finding."""

        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "source_tool": self.source_tool,
            "evidence": self.evidence,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ReportDocument:
    """Canonical SABER report document."""

    report_id: str
    mission_name: str
    target: str
    generated_at: datetime
    executive_summary: str
    observations: list[ReportObservation] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate report document."""

        if not self.report_id.strip():
            raise ValueError("ReportDocument.report_id cannot be empty.")
        if not self.mission_name.strip():
            raise ValueError("ReportDocument.mission_name cannot be empty.")
        if not self.target.strip():
            raise ValueError("ReportDocument.target cannot be empty.")
        if not self.executive_summary.strip():
            raise ValueError("ReportDocument.executive_summary cannot be empty.")

    def severity_counts(self) -> dict[str, int]:
        """Return finding counts by severity."""

        counts = {severity.value: 0 for severity in ReportSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def highest_severity(self) -> ReportSeverity:
        """Return highest finding severity."""

        if not self.findings:
            return ReportSeverity.INFO

        return min((finding.severity for finding in self.findings), key=lambda severity: SEVERITY_ORDER[severity])

    def sorted_findings(self) -> list[ReportFinding]:
        """Return findings sorted by severity."""

        return sorted(self.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])

    def priority_findings(self, limit: int = 5) -> list[ReportFinding]:
        """Return top priority findings."""

        return self.sorted_findings()[:limit]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible report."""

        return {
            "report_id": self.report_id,
            "mission_name": self.mission_name,
            "target": self.target,
            "generated_at": self.generated_at.isoformat(),
            "executive_summary": self.executive_summary,
            "highest_severity": self.highest_severity().value,
            "severity_counts": self.severity_counts(),
            "finding_count": len(self.findings),
            "observation_count": len(self.observations),
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
            "observations": [observation.to_dict() for observation in self.observations],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Return report JSON."""

        return json.dumps(self.to_dict(), indent=indent, sort_keys=False, default=str)


class JsonExporter:
    """Build and export canonical SABER report documents."""

    def build_document(
        self,
        mission_name: str,
        target: str,
        observations: list[Any] | None = None,
        findings: list[Any] | None = None,
        metadata: dict[str, Any] | None = None,
        executive_summary: str | None = None,
        report_id: str | None = None,
        generated_at: datetime | None = None,
    ) -> ReportDocument:
        """Build canonical report document from mixed evidence objects."""

        report_observations = [self.normalize_observation(observation) for observation in observations or []]
        report_findings = [self.normalize_finding(finding) for finding in findings or []]

        summary = executive_summary or self._build_executive_summary(report_findings, report_observations)

        return ReportDocument(
            report_id=report_id or f"report_{uuid4().hex[:12]}",
            mission_name=mission_name,
            target=target,
            generated_at=generated_at or datetime.now(UTC),
            executive_summary=summary,
            observations=report_observations,
            findings=report_findings,
            metadata=metadata or {},
        )

    def export(self, document: ReportDocument, output_path: str | Path) -> Path:
        """Write report document to JSON file."""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document.to_json(indent=2), encoding="utf-8")
        return path

    def export_dict(self, document: ReportDocument) -> dict[str, Any]:
        """Return document as dictionary."""

        return document.to_dict()

    def normalize_observation(self, observation: Any) -> ReportObservation:
        """Normalize observation-like object."""

        if isinstance(observation, ReportObservation):
            return observation

        if isinstance(observation, dict):
            return ReportObservation(
                kind=str(observation.get("kind") or "generic"),
                summary=str(observation.get("summary") or observation.get("message") or "Observation."),
                source_tool=observation.get("source_tool") or observation.get("tool_name"),
                data=self._dict_or_empty(observation.get("data")),
                metadata=self._dict_or_empty(observation.get("metadata")),
            )

        return ReportObservation(
            kind=str(getattr(observation, "kind", None) or "generic"),
            summary=str(getattr(observation, "summary", None) or getattr(observation, "message", None) or "Observation."),
            source_tool=getattr(observation, "source_tool", None) or getattr(observation, "tool_name", None),
            data=self._dict_or_empty(getattr(observation, "data", None)),
            metadata=self._dict_or_empty(getattr(observation, "metadata", None)),
        )

    def normalize_finding(self, finding: Any) -> ReportFinding:
        """Normalize finding-like object."""

        if isinstance(finding, ReportFinding):
            return finding

        if isinstance(finding, dict):
            return ReportFinding(
                title=str(finding.get("title") or "Finding"),
                severity=self.severity_from_value(finding.get("severity")),
                description=str(finding.get("description") or "No description provided."),
                source_tool=finding.get("source_tool"),
                evidence=self._dict_or_empty(finding.get("evidence")),
                references=self._list_of_strings(finding.get("references")),
                metadata=self._dict_or_empty(finding.get("metadata")),
            )

        return ReportFinding(
            title=str(getattr(finding, "title", None) or "Finding"),
            severity=self.severity_from_value(getattr(finding, "severity", None)),
            description=str(getattr(finding, "description", None) or "No description provided."),
            source_tool=getattr(finding, "source_tool", None),
            evidence=self._dict_or_empty(getattr(finding, "evidence", None)),
            references=self._list_of_strings(getattr(finding, "references", None)),
            metadata=self._dict_or_empty(getattr(finding, "metadata", None)),
        )

    @staticmethod
    def severity_from_value(value: Any) -> ReportSeverity:
        """Normalize severity value."""

        if isinstance(value, ReportSeverity):
            return value

        raw = getattr(value, "value", value)
        if raw is None:
            return ReportSeverity.UNKNOWN

        normalized = str(raw).strip().lower()
        mapping = {
            "info": ReportSeverity.INFO,
            "informational": ReportSeverity.INFO,
            "low": ReportSeverity.LOW,
            "medium": ReportSeverity.MEDIUM,
            "med": ReportSeverity.MEDIUM,
            "high": ReportSeverity.HIGH,
            "critical": ReportSeverity.CRITICAL,
            "crit": ReportSeverity.CRITICAL,
            "unknown": ReportSeverity.UNKNOWN,
        }
        return mapping.get(normalized, ReportSeverity.UNKNOWN)

    @staticmethod
    def _dict_or_empty(value: Any) -> dict[str, Any]:
        """Return dict or empty dict."""

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list_of_strings(value: Any) -> list[str]:
        """Return list of strings."""

        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    @staticmethod
    def _build_executive_summary(
        findings: list[ReportFinding],
        observations: list[ReportObservation],
    ) -> str:
        """Build deterministic executive summary."""

        counts = {severity.value: 0 for severity in ReportSeverity}
        for finding in findings:
            counts[finding.severity.value] += 1

        if not findings:
            return (
                f"SABER completed evidence collection and recorded {len(observations)} observations. "
                "No reportable findings were included in the supplied evidence."
            )

        highest = min((finding.severity for finding in findings), key=lambda severity: SEVERITY_ORDER[severity])
        return (
            f"SABER identified {len(findings)} findings and {len(observations)} observations. "
            f"The highest finding severity is {highest.value}. "
            f"Finding counts: critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, info={counts['info']}, "
            f"unknown={counts['unknown']}."
        )
