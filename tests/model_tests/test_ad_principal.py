

"""Tests for SABER Active Directory principal models.

This file verifies that `saber.models.ad_principal` correctly models AD
principals and relationships without performing LDAP, BloodHound, Kerberos, or
network operations.
"""

from __future__ import annotations

import pytest

from saber.models.ad_principal import (
    ADPrincipal,
    ADPrincipalType,
    ADRelationship,
    ADRelationshipType,
)
from saber.models.evidence import EvidenceRecord, EvidenceType


def make_evidence(evidence_id: str = "ev_ad_1") -> EvidenceRecord:
    """Create reusable evidence for AD relationship tests.

    Args:
        evidence_id: Evidence identifier to assign.

    Returns:
        A validated EvidenceRecord object.
    """

    return EvidenceRecord(
        evidence_id=evidence_id,
        type=EvidenceType.TOOL_TEXT,
        title="BloodHound edge output",
        file_path="evidence/ad/edges.json",
    )


def make_principal(
    principal_id: str = "adp_user_1",
    principal_type: ADPrincipalType = ADPrincipalType.USER,
    name: str = "alice",
) -> ADPrincipal:
    """Create a reusable AD principal for tests.

    Args:
        principal_id: Principal identifier to assign.
        principal_type: AD principal type to assign.
        name: Principal name to assign.

    Returns:
        A validated ADPrincipal object.
    """

    return ADPrincipal(
        principal_id=principal_id,
        type=principal_type,
        name=name,
        distinguished_name="CN=Alice,CN=Users,DC=internal,DC=local",
        domain="internal.local",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1105",
        object_guid="550e8400-e29b-41d4-a716-446655440000",
        enabled=True,
        tags=[" AD ", "ad", "Tier 1"],
    )


class TestADPrincipalCreation:
    """Validate ADPrincipal construction and normalization."""

    def test_valid_ad_principal(self) -> None:
        """A valid AD principal should normalize text fields and tags."""

        principal = ADPrincipal(
            principal_id=" adp_1 ",
            type=ADPrincipalType.USER,
            name=" Alice ",
            distinguished_name=" CN=Alice,CN=Users,DC=internal,DC=local ",
            domain=" internal.local ",
            sid=" S-1-5-21-1111111111-2222222222-3333333333-1105 ",
            object_guid=" 550e8400-e29b-41d4-a716-446655440000 ",
            enabled=True,
            high_value=False,
            owned=False,
            risk_score=4.5,
            tags=[" AD ", "ad", "Tier 1"],
        )

        assert principal.principal_id == "adp_1"
        assert principal.type == ADPrincipalType.USER
        assert principal.name == "Alice"
        assert principal.distinguished_name == "CN=Alice,CN=Users,DC=internal,DC=local"
        assert principal.domain == "internal.local"
        assert principal.sid == "S-1-5-21-1111111111-2222222222-3333333333-1105"
        assert principal.object_guid == "550e8400-e29b-41d4-a716-446655440000"
        assert principal.enabled is True
        assert principal.high_value is False
        assert principal.owned is False
        assert principal.risk_score == 4.5
        assert principal.tags == ["ad", "tier_1"]

    def test_auto_generated_principal_id_has_expected_prefix(self) -> None:
        """Principal IDs should be generated when omitted."""

        principal = ADPrincipal(type=ADPrincipalType.GROUP, name="Domain Admins")

        assert principal.principal_id.startswith("adp_")
        assert len(principal.principal_id) > len("adp_")

    def test_empty_optional_text_becomes_none(self) -> None:
        """Optional AD principal text fields should normalize empty strings to None."""

        principal = ADPrincipal(
            type=ADPrincipalType.COMPUTER,
            name="DC01$",
            distinguished_name="   ",
            domain="   ",
            sid=None,
            object_guid="   ",
        )

        assert principal.distinguished_name is None
        assert principal.domain is None
        assert principal.sid is None
        assert principal.object_guid is None


class TestADPrincipalValidation:
    """Validate ADPrincipal error handling."""

    @pytest.mark.parametrize("principal_id", ["", "   ", "adp 1"])
    def test_invalid_principal_id_raises_error(self, principal_id: str) -> None:
        """Empty or whitespace-containing principal IDs should be rejected."""

        with pytest.raises(ValueError):
            ADPrincipal(principal_id=principal_id, type=ADPrincipalType.USER, name="alice")

    @pytest.mark.parametrize(
        "sid",
        [
            "not-a-sid",
            "S-ABC-5-21",
            "S-1-5-21-notnumeric",
        ],
    )
    def test_invalid_sid_raises_error(self, sid: str) -> None:
        """Malformed SID values should be rejected."""

        with pytest.raises(ValueError):
            ADPrincipal(type=ADPrincipalType.USER, name="alice", sid=sid)

    def test_empty_sid_normalizes_to_none(self) -> None:
        """Empty optional SID values should normalize to None."""

        principal = ADPrincipal(type=ADPrincipalType.USER, name="alice", sid="   ")

        assert principal.sid is None

    @pytest.mark.parametrize("risk_score", [-0.1, 10.1])
    def test_risk_score_out_of_bounds_raises_error(self, risk_score: float) -> None:
        """Risk score should be constrained to 0.0 through 10.0."""

        with pytest.raises(ValueError):
            ADPrincipal(
                type=ADPrincipalType.USER,
                name="alice",
                risk_score=risk_score,
            )


class TestADPrincipalHelpers:
    """Validate ADPrincipal helper properties and copy methods."""

    def test_type_helper_properties(self) -> None:
        """Principal type helpers should classify user, computer, and group objects."""

        user = make_principal(principal_type=ADPrincipalType.USER)
        service_account = make_principal(
            principal_id="adp_svc_1",
            principal_type=ADPrincipalType.SERVICE_ACCOUNT,
            name="svc_sql",
        )
        computer = make_principal(
            principal_id="adp_computer_1",
            principal_type=ADPrincipalType.COMPUTER,
            name="DC01$",
        )
        group = make_principal(
            principal_id="adp_group_1",
            principal_type=ADPrincipalType.GROUP,
            name="Domain Admins",
        )

        assert user.is_user
        assert service_account.is_user
        assert not computer.is_user
        assert computer.is_computer
        assert not user.is_computer
        assert group.is_group
        assert not user.is_group

    def test_high_impact_property(self) -> None:
        """High impact should reflect high_value, owned, or high risk score."""

        normal = make_principal()
        high_value = make_principal(principal_id="adp_high", name="Domain Admins").mark_high_value()
        owned = make_principal(principal_id="adp_owned", name="owned_user").mark_owned()
        risky = make_principal(principal_id="adp_risky", name="risky_user").model_copy(
            update={"risk_score": 8.0}
        )

        assert not normal.is_high_impact
        assert high_value.is_high_impact
        assert owned.is_high_impact
        assert risky.is_high_impact

    def test_marker_methods_return_updated_copies(self) -> None:
        """mark_owned and mark_high_value should return copied principals."""

        principal = make_principal()

        owned = principal.mark_owned()
        high_value = principal.mark_high_value()

        assert principal.owned is False
        assert principal.high_value is False
        assert owned.owned is True
        assert high_value.high_value is True

    def test_to_agent_dict_and_report_dict(self) -> None:
        """AD principal serialization should expose normalized metadata."""

        principal = make_principal()
        expected = {
            "principal_id": "adp_user_1",
            "type": "user",
            "name": "alice",
            "distinguished_name": "CN=Alice,CN=Users,DC=internal,DC=local",
            "domain": "internal.local",
            "sid": "S-1-5-21-1111111111-2222222222-3333333333-1105",
            "object_guid": "550e8400-e29b-41d4-a716-446655440000",
            "enabled": True,
            "high_value": False,
            "owned": False,
            "risk_score": 0.0,
            "tags": ["ad", "tier_1"],
        }

        assert principal.to_agent_dict() == expected
        assert principal.to_report_dict() == expected


class TestADRelationshipCreation:
    """Validate ADRelationship construction and serialization."""

    def test_valid_relationship(self) -> None:
        """A valid relationship should connect two distinct principals."""

        source = make_principal()
        target = make_principal(
            principal_id="adp_group_1",
            principal_type=ADPrincipalType.GROUP,
            name="Domain Admins",
        )
        relationship = ADRelationship(
            relationship_id=" adr_1 ",
            type=ADRelationshipType.MEMBER_OF,
            source=source,
            target=target,
            confidence=0.9,
            evidence=[make_evidence()],
        )

        assert relationship.relationship_id == "adr_1"
        assert relationship.type == ADRelationshipType.MEMBER_OF
        assert relationship.source == source
        assert relationship.target == target
        assert relationship.confidence == 0.9
        assert relationship.evidence[0].evidence_id == "ev_ad_1"
        assert relationship.discovered_at.tzinfo is not None

    def test_auto_generated_relationship_id_has_expected_prefix(self) -> None:
        """Relationship IDs should be generated when omitted."""

        relationship = ADRelationship(
            type=ADRelationshipType.MEMBER_OF,
            source=make_principal(),
            target=make_principal(
                principal_id="adp_group_1",
                principal_type=ADPrincipalType.GROUP,
                name="Domain Admins",
            ),
        )

        assert relationship.relationship_id.startswith("adr_")
        assert len(relationship.relationship_id) > len("adr_")

    @pytest.mark.parametrize("relationship_id", ["", "   ", "adr 1"])
    def test_invalid_relationship_id_raises_error(self, relationship_id: str) -> None:
        """Empty or whitespace-containing relationship IDs should be rejected."""

        with pytest.raises(ValueError):
            ADRelationship(
                relationship_id=relationship_id,
                type=ADRelationshipType.MEMBER_OF,
                source=make_principal(),
                target=make_principal(
                    principal_id="adp_group_1",
                    principal_type=ADPrincipalType.GROUP,
                    name="Domain Admins",
                ),
            )

    @pytest.mark.parametrize("confidence", [-0.1, 1.1])
    def test_confidence_out_of_bounds_raises_error(self, confidence: float) -> None:
        """Relationship confidence should be constrained to 0.0 through 1.0."""

        with pytest.raises(ValueError):
            ADRelationship(
                type=ADRelationshipType.MEMBER_OF,
                source=make_principal(),
                target=make_principal(
                    principal_id="adp_group_1",
                    principal_type=ADPrincipalType.GROUP,
                    name="Domain Admins",
                ),
                confidence=confidence,
            )

    def test_same_principal_relationship_raises_error_for_normal_edges(self) -> None:
        """Most relationship types should require distinct source and target principals."""

        principal = make_principal()

        with pytest.raises(ValueError):
            ADRelationship(
                type=ADRelationshipType.MEMBER_OF,
                source=principal,
                target=principal,
            )

    def test_roastable_relationship_can_reference_same_principal(self) -> None:
        """Roastability edges should be allowed as self-referential facts."""

        principal = make_principal()
        relationship = ADRelationship(
            type=ADRelationshipType.KERBEROASTABLE,
            source=principal,
            target=principal,
        )

        assert relationship.source == principal
        assert relationship.target == principal


class TestADRelationshipHelpers:
    """Validate ADRelationship helper properties and serialization."""

    def test_high_impact_relationship_type(self) -> None:
        """Privilege-control relationship types should be high impact."""

        relationship = ADRelationship(
            type=ADRelationshipType.GENERIC_ALL,
            source=make_principal(),
            target=make_principal(
                principal_id="adp_target_1",
                principal_type=ADPrincipalType.COMPUTER,
                name="DC01$",
            ),
        )

        assert relationship.is_high_impact

    def test_high_value_target_relationship_is_high_impact(self) -> None:
        """Relationships to high-value targets should be high impact."""

        target = make_principal(
            principal_id="adp_domain_admins",
            principal_type=ADPrincipalType.GROUP,
            name="Domain Admins",
        ).mark_high_value()
        relationship = ADRelationship(
            type=ADRelationshipType.MEMBER_OF,
            source=make_principal(),
            target=target,
        )

        assert relationship.is_high_impact

    def test_low_impact_relationship(self) -> None:
        """Normal relationships to normal targets should not be high impact."""

        relationship = ADRelationship(
            type=ADRelationshipType.MEMBER_OF,
            source=make_principal(),
            target=make_principal(
                principal_id="adp_group_1",
                principal_type=ADPrincipalType.GROUP,
                name="Helpdesk",
            ),
        )

        assert not relationship.is_high_impact

    def test_to_agent_dict_and_report_dict(self) -> None:
        """AD relationship serialization should include graph edge metadata."""

        source = make_principal()
        target = make_principal(
            principal_id="adp_group_1",
            principal_type=ADPrincipalType.GROUP,
            name="Domain Admins",
        ).mark_high_value()
        relationship = ADRelationship(
            relationship_id="adr_1",
            type=ADRelationshipType.MEMBER_OF,
            source=source,
            target=target,
            confidence=0.8,
            evidence=[make_evidence()],
        )

        agent_dict = relationship.to_agent_dict()

        assert agent_dict["relationship_id"] == "adr_1"
        assert agent_dict["type"] == "member_of"
        assert agent_dict["source"] == source.to_agent_dict()
        assert agent_dict["target"] == target.to_agent_dict()
        assert agent_dict["confidence"] == 0.8
        assert agent_dict["evidence_refs"] == ["ev_ad_1"]
        assert agent_dict["high_impact"] is True
        assert "discovered_at" in agent_dict
        assert relationship.to_report_dict() == agent_dict