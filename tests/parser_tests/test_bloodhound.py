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
        # F3: relationships are canonical "note" observations so StateMerger folds
        # them in; the graph detail moved into data["metadata"].
        assert result.observations[0].kind == "note"
        assert result.observations[0].data["title"] == "AD relationship: alice -MemberOf-> Helpdesk"
        assert result.observations[0].data["metadata"]["source"] == "alice"
        assert result.observations[0].data["metadata"]["relationship"] == "MemberOf"
        assert result.observations[0].data["metadata"]["target"] == "Helpdesk"
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
        # ONE edge is ONE relationship. This used to assert 2/2, because the
        # collection was consumed twice — once as relationships and again as a path —
        # inventing an attack path from a single edge and codifying it as correct.
        # Fabricating a finding is the worst failure mode for an evidence-first tool.
        assert len(result.observations) == 1
        assert len(result.findings) == 1

        relationship = result.findings[0]
        assert relationship.metadata["finding_type"] == "ad_relationship"
        assert relationship.severity == ParserSeverity.HIGH
        assert relationship.evidence["source"] == "alice"
        assert relationship.evidence["relationship"] == "GenericAll"
        assert relationship.evidence["target"] == "Domain Admins"

        assert not any(
            finding.metadata["finding_type"] == "ad_attack_path" for finding in result.findings
        ), "a single edge must not become an attack path"

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
        assert result.observations[0].kind == "note"
        assert result.observations[0].data["metadata"]["source"] == "alice"
        assert result.observations[0].data["metadata"]["target"] == "Domain Admins"
        assert result.observations[0].data["metadata"]["path_length"] == 2
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
        assert result.observations[0].data["metadata"]["source"] == "alice"
        assert result.observations[0].data["metadata"]["target"] == "Domain Admins"

    def test_parse_entities(self) -> None:
        """Entities map onto canonical kinds: users->account, computers->host."""

        data = {
            "users": [{"name": "alice"}],
            "groups": [{"name": "Helpdesk"}],
            "computers": [{"name": "HOST01"}],
        }

        result = BloodHoundParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 3
        assert {obs.kind for obs in result.observations} == {"account", "host", "note"}

        account = next(obs for obs in result.observations if obs.kind == "account")
        host = next(obs for obs in result.observations if obs.kind == "host")
        group_note = next(obs for obs in result.observations if obs.kind == "note")

        assert account.data["username"] == "alice"
        assert host.data["address"] == "host01"
        assert group_note.data["title"] == "AD group: Helpdesk"

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
        assert result.observations[0].data["metadata"]["source"] == "alice"

    def test_no_data_fails(self) -> None:
        """No parseable data should fail."""

        result = BloodHoundParser().parse_json({"nothing": []})

        assert result.success is False
        assert result.errors == ["No BloodHound relationships or paths could be parsed."]
