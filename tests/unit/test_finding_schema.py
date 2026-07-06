"""Schema-focused tests for SABER finding models.

These tests validate the JSON-schema and JSON-serialization behavior of the
finding-related Pydantic models. They complement `tests/model_tests/test_finding_model.py`,
which focuses on validation rules and helper methods.
"""

from __future__ import annotations

import json
from typing import Any

from saber.models.finding import (
    Finding,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingStatus,
    RemediationStep,
    VerificationStatus,
)


def schema_text(schema: dict[str, Any]) -> str:
    """Return deterministic JSON text for schema assertions.

    Args:
        schema: JSON schema dictionary.

    Returns:
        Sorted JSON string.
    """

    return json.dumps(schema, sort_keys=True)


class TestFindingJsonSchema:
    """Validate the generated JSON schema for Finding."""

    def test_finding_schema_contains_core_properties(self) -> None:
        """Finding schema should expose the core reporting fields."""

        schema = Finding.model_json_schema()
        properties = schema["properties"]

        expected_fields = {
            "finding_id",
            "title",
            "description",
            "severity",
            "confidence",
            "verification_status",
            "status",
            "affected_targets",
            "evidence",
            "cvss_score",
            "cvss_vector",
            "cwe_ids",
            "cve_ids",
            "business_impact",
            "technical_impact",
            "remediation",
            "references",
            "tags",
            "first_seen",
            "last_seen",
            "metadata",
        }

        assert expected_fields.issubset(properties.keys())
        assert schema["title"] == "Finding"
        assert schema["type"] == "object"

    def test_finding_schema_contains_expected_enum_values(self) -> None:
        """Finding schema should include all finding enum values."""

        text = schema_text(Finding.model_json_schema())

        for value in ["info", "low", "medium", "high", "critical"]:
            assert value in text

        for value in ["candidate", "unverified", "verified", "false_positive", "accepted_risk"]:
            assert value in text

        for value in ["open", "in_review", "remediated", "risk_accepted", "closed"]:
            assert value in text

    def test_nested_model_definitions_are_present(self) -> None:
        """Finding schema should include nested remediation and reference definitions."""

        schema = Finding.model_json_schema()
        definitions = schema.get("$defs", {})

        assert "RemediationStep" in definitions
        assert "FindingReference" in definitions

    def test_remediation_and_reference_fields_are_arrays(self) -> None:
        """Nested remediation and reference fields should be represented as arrays."""

        properties = Finding.model_json_schema()["properties"]

        assert properties["remediation"]["type"] == "array"
        assert properties["references"]["type"] == "array"


class TestRemediationStepJsonSchema:
    """Validate the JSON schema for RemediationStep."""

    def test_remediation_step_schema_contains_expected_fields(self) -> None:
        """RemediationStep schema should expose title, description, and priority."""

        schema = RemediationStep.model_json_schema()
        properties = schema["properties"]

        assert schema["title"] == "RemediationStep"
        assert {"title", "description", "priority"}.issubset(properties.keys())
        assert "title" in schema["required"]
        assert "description" in schema["required"]

    def test_remediation_step_validates_from_json_schema_shape(self) -> None:
        """RemediationStep should validate common JSON-style input."""

        step = RemediationStep.model_validate(
            {
                "title": "Patch affected service",
                "description": "Apply the vendor patch and restart the service.",
                "priority": 1,
            }
        )

        assert step.title == "Patch affected service"
        assert step.description == "Apply the vendor patch and restart the service."
        assert step.priority == 1


class TestFindingReferenceJsonSchema:
    """Validate the JSON schema for FindingReference."""

    def test_finding_reference_schema_contains_expected_fields(self) -> None:
        """FindingReference schema should expose label, url, and source."""

        schema = FindingReference.model_json_schema()
        properties = schema["properties"]

        assert schema["title"] == "FindingReference"
        assert {"label", "url", "source"}.issubset(properties.keys())
        assert "label" in schema["required"]

    def test_finding_reference_validates_json_style_input(self) -> None:
        """FindingReference should validate common JSON-style input."""

        reference = FindingReference.model_validate(
            {
                "label": "Vendor advisory",
                "url": "https://example.com/advisory",
                "source": "vendor",
            }
        )

        assert reference.label == "Vendor advisory"
        assert reference.url == "https://example.com/advisory"
        assert reference.source == "vendor"


class TestFindingJsonRoundTrip:
    """Validate finding JSON input and output behavior."""

    def test_finding_validates_enum_strings_from_json_data(self) -> None:
        """Finding should accept JSON-style strings for enum fields."""

        finding = Finding.model_validate(
            {
                "finding_id": "finding_1",
                "title": "Example exposed service",
                "description": "An example service was reachable during testing.",
                "severity": "high",
                "confidence": "medium",
                "verification_status": "candidate",
                "status": "open",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "cwe_ids": ["CWE-200"],
                "cve_ids": ["CVE-2024-1234"],
                "business_impact": "Could expose sensitive service metadata.",
                "technical_impact": "Remote users can reach the service banner.",
                "remediation": [
                    {
                        "title": "Restrict access",
                        "description": "Limit exposure to approved source networks.",
                        "priority": 1,
                    }
                ],
                "references": [
                    {
                        "label": "Internal standard",
                        "url": "https://example.com/standard",
                        "source": "internal",
                    }
                ],
                "tags": ["web", "exposure"],
                "metadata": {"source": "unit-test"},
            }
        )

        assert finding.severity == FindingSeverity.HIGH
        assert finding.confidence == FindingConfidence.MEDIUM
        assert finding.verification_status == VerificationStatus.CANDIDATE
        assert finding.status == FindingStatus.OPEN
        assert finding.remediation[0].title == "Restrict access"
        assert finding.references[0].label == "Internal standard"

    def test_finding_model_dump_json_uses_enum_values(self) -> None:
        """Finding JSON serialization should use stable enum string values."""

        finding = Finding.model_validate(
            {
                "finding_id": "finding_2",
                "title": "Informational finding",
                "description": "Informational observation for reporting.",
                "severity": FindingSeverity.INFO,
                "confidence": FindingConfidence.HIGH,
                "verification_status": VerificationStatus.UNVERIFIED,
                "status": FindingStatus.IN_REVIEW,
            }
        )

        dumped = finding.model_dump(mode="json")

        assert dumped["severity"] == "info"
        assert dumped["confidence"] == "high"
        assert dumped["verification_status"] == "unverified"
        assert dumped["status"] == "in_review"
        assert dumped["finding_id"] == "finding_2"

    def test_finding_model_validate_json_round_trip(self) -> None:
        """Finding should round-trip through JSON validation."""

        json_payload = json.dumps(
            {
                "finding_id": "finding_3",
                "title": "Low risk finding",
                "description": "Low risk observation for the evidence bundle.",
                "severity": "low",
                "confidence": "low",
                "verification_status": "candidate",
                "status": "open",
            }
        )

        finding = Finding.model_validate_json(json_payload)
        dumped_json = finding.model_dump_json()
        reparsed = Finding.model_validate_json(dumped_json)

        assert reparsed.finding_id == finding.finding_id
        assert reparsed.severity == FindingSeverity.LOW
        assert reparsed.confidence == FindingConfidence.LOW
        assert reparsed.verification_status == VerificationStatus.CANDIDATE
        assert reparsed.status == FindingStatus.OPEN
