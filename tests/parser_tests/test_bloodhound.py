"""Tests for BloodHoundParser."""

from __future__ import annotations

from saber.parsers.base import ParserSeverity
from saber.parsers.bloodhound import BloodHoundParser


class TestBloodHoundParser:
    """Validate BloodHound parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = BloodHoundParser().parse_text("")

        assert result.success is False
        assert result.errors == ["BloodHound output is empty."]

    def test_non_json_text_fails(self) -> None:
        """Non-JSON text should fail."""

        result = BloodHoundParser().parse_text("not json")

        assert result.success is False
        assert result.errors == ["BloodHound parser currently expects JSON-compatible output."]

    def test_parse_relationships(self) -> None:
        """Relationships should produce observations."""

        data = {
            "relationships": [
                {
                    "source": "alice",
                    "relationship": "MemberOf",
                    "target": "Helpdesk",
                }
            ]
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 1
        assert result.observations[0].kind == "ad_relationship"
        assert result.observations[0].data["source"] == "alice"
        assert result.observations[0].data["relationship"] == "MemberOf"
        assert result.observations[0].data["target"] == "Helpdesk"
        assert result.findings == []

    def test_high_risk_relationship_creates_finding(self) -> None:
        """High-risk AD relationship should create finding."""

        data = {
            "edges": [
                {
                    "source": "alice",
                    "edge_type": "GenericAll",
                    "target": "Domain Admins",
                }
            ]
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 2
        assert len(result.findings) == 2

        relationship = next(finding for finding in result.findings if finding.metadata["finding_type"] == "ad_relationship")
        path = next(finding for finding in result.findings if finding.metadata["finding_type"] == "ad_attack_path")

        assert relationship.severity == ParserSeverity.HIGH
        assert relationship.evidence["source"] == "alice"
        assert relationship.evidence["relationship"] == "GenericAll"
        assert relationship.evidence["target"] == "Domain Admins"

        assert path.severity == ParserSeverity.HIGH
        assert path.evidence["source"] == "alice"
        assert path.evidence["target"] == "Domain Admins"

    def test_medium_risk_relationship_creates_finding(self) -> None:
        """High-risk relationship to non-high-value target should be medium."""

        data = {
            "relationships": [
                {
                    "source": "bob",
                    "relationship": "CanRDP",
                    "target": "workstation01",
                }
            ]
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].severity == ParserSeverity.MEDIUM

    def test_parse_attack_path_to_domain_admins(self) -> None:
        """Attack path to high-value target should create high finding."""

        data = {
            "paths": [
                {
                    "source": "alice",
                    "target": "Domain Admins",
                    "edges": [
                        {"source": "alice", "relationship": "MemberOf", "target": "Helpdesk"},
                        {"source": "Helpdesk", "relationship": "GenericAll", "target": "Domain Admins"},
                    ],
                }
            ]
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 1
        assert result.observations[0].kind == "ad_path"
        assert result.observations[0].data["source"] == "alice"
        assert result.observations[0].data["target"] == "Domain Admins"
        assert result.observations[0].data["path_length"] == 2
        assert len(result.findings) == 1
        assert result.findings[0].severity == ParserSeverity.HIGH
        assert result.findings[0].metadata["finding_type"] == "ad_attack_path"

    def test_parse_path_endpoint_from_edges(self) -> None:
        """Path endpoints should be inferred from edge list."""

        data = {
            "attack_paths": [
                {
                    "edges": [
                        {"source": "alice", "relationship": "MemberOf", "target": "Helpdesk"},
                        {"source": "Helpdesk", "relationship": "GenericAll", "target": "Domain Admins"},
                    ],
                }
            ]
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert result.observations[0].data["source"] == "alice"
        assert result.observations[0].data["target"] == "Domain Admins"

    def test_parse_entities(self) -> None:
        """Entities should produce ad_entity observations."""

        data = {
            "users": [{"name": "alice"}],
            "groups": [{"name": "Helpdesk"}],
            "computers": [{"name": "HOST01"}],
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 3
        assert {obs.data["entity_type"] for obs in result.observations} == {"user", "group", "computer"}

    def test_parse_list_records(self) -> None:
        """List records should parse."""

        data = [
            {"source": "alice", "relationship": "MemberOf", "target": "Helpdesk"},
            {"source": "bob", "relationship": "AdminTo", "target": "DC01"},
        ]

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 2
        assert len(result.findings) == 1

    def test_parse_json_text(self) -> None:
        """JSON text should route to parse_json."""

        text = '{"relationships":[{"source":"alice","relationship":"MemberOf","target":"Helpdesk"}]}'

        result = BloodHoundParser().parse_text(text)

        assert result.success is True
        assert result.observations[0].data["source"] == "alice"

    def test_no_data_fails(self) -> None:
        """No parseable data should fail."""

        result = BloodHoundParser().parse_json({"nothing": []})

        assert result.success is False
        assert result.errors == ["No BloodHound relationships or paths could be parsed."]
