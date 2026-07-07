

"""Active Directory principal models used across SABER.

This file defines safe data structures for Active Directory objects and
relationships discovered during authorized internal assessments. These models do
not perform LDAP, BloodHound, NetExec, or Kerberos operations. They only represent
normalized AD graph data for agents, evidence storage, and reports.

Inputs:
    - Parsed LDAP/BloodHound/NetExec-style output from authorized wrappers.
    - Operator-provided AD context.
    - Evidence records that support discovered AD relationships.

Outputs:
    - Normalized ADPrincipal and ADRelationship objects.
    - Agent-safe and report-safe dictionaries for graph analysis and reporting.

Used by:
    - saber.tools.active_directory.* wrappers
    - saber.agents.network
    - saber.agents.post_exploit
    - saber.models.finding
    - saber.core.evidence_store
    - saber.reporting exporters
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from saber.models.evidence import EvidenceRecord


class ADPrincipalType(StrEnum):
    """Supported Active Directory principal types.

    Values:
        USER: Normal user account.
        GROUP: AD security or distribution group.
        COMPUTER: Domain-joined computer account.
        DOMAIN: Active Directory domain object.
        ORGANIZATIONAL_UNIT: Organizational Unit object.
        SERVICE_ACCOUNT: Service account.
        GMSA: Group Managed Service Account.
        UNKNOWN: Principal type is unknown or not mapped yet.
    """

    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DOMAIN = "domain"
    ORGANIZATIONAL_UNIT = "organizational_unit"
    SERVICE_ACCOUNT = "service_account"
    GMSA = "gmsa"
    UNKNOWN = "unknown"


class ADRelationshipType(StrEnum):
    """Supported Active Directory relationship types.

    Values:
        MEMBER_OF: Source principal is a member of target group.
        ADMIN_TO: Source principal has admin rights over target.
        HAS_SESSION: Source computer has a session for target user.
        CAN_RDP: Source principal can RDP to target computer.
        CAN_PSREMOTE: Source principal can PowerShell Remoting to target.
        ALLOWED_TO_DELEGATE: Source principal can delegate to target.
        KERBEROASTABLE: Principal has SPN exposure for Kerberoasting.
        ASREP_ROASTABLE: User does not require Kerberos pre-authentication.
        OWNS: Source principal owns target object.
        GENERIC_ALL: Source principal has GenericAll over target.
        GENERIC_WRITE: Source principal has GenericWrite over target.
        WRITE_DACL: Source principal can modify target DACL.
        WRITE_OWNER: Source principal can modify target owner.
        FORCE_CHANGE_PASSWORD: Source principal can reset target password.
        DCSYNC: Source principal can replicate directory secrets.
        OTHER: Relationship exists but is not mapped to a known type.
    """

    MEMBER_OF = "member_of"
    ADMIN_TO = "admin_to"
    HAS_SESSION = "has_session"
    CAN_RDP = "can_rdp"
    CAN_PSREMOTE = "can_psremote"
    ALLOWED_TO_DELEGATE = "allowed_to_delegate"
    KERBEROASTABLE = "kerberoastable"
    ASREP_ROASTABLE = "asrep_roastable"
    OWNS = "owns"
    GENERIC_ALL = "generic_all"
    GENERIC_WRITE = "generic_write"
    WRITE_DACL = "write_dacl"
    WRITE_OWNER = "write_owner"
    FORCE_CHANGE_PASSWORD = "force_change_password"
    DCSYNC = "dcsync"
    OTHER = "other"


class ADPrincipal(BaseModel):
    """Normalized Active Directory principal.

    Args:
        principal_id: Stable SABER principal identifier.
        type: AD principal type.
        name: Short account or object name.
        distinguished_name: Optional LDAP distinguished name.
        domain: Optional AD domain or realm.
        sid: Optional Windows security identifier.
        object_guid: Optional AD object GUID.
        enabled: Optional enabled/disabled account state.
        high_value: Whether the object is high value, such as Domain Admins.
        owned: Whether the object is controlled in an authorized lab/assessment context.
        risk_score: Analyst/tool risk score from 0.0 to 10.0.
        tags: Normalized labels for filtering, graphing, and reporting.
        created_at: UTC timestamp when this model object was created.
        metadata: Optional structured context from AD tools.

    Returns:
        A validated AD principal object.
    """

    principal_id: str = Field(default_factory=lambda: f"adp_{uuid4().hex}")
    type: ADPrincipalType = ADPrincipalType.UNKNOWN
    name: str = Field(..., min_length=1)
    distinguished_name: str | None = None
    domain: str | None = None
    sid: str | None = None
    object_guid: str | None = None
    enabled: bool | None = None
    high_value: bool = False
    owned: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "principal_id",
        "name",
        "distinguished_name",
        "domain",
        "sid",
        "object_guid",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize AD principal text fields.

        Args:
            value: Raw string or None.

        Returns:
            Stripped string, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("principal_id")
    @classmethod
    def validate_principal_id(cls, principal_id: str) -> str:
        """Validate a principal ID.

        Args:
            principal_id: Normalized principal identifier.

        Returns:
            The validated principal ID.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        if not principal_id:
            raise ValueError("principal_id cannot be empty")
        if any(character.isspace() for character in principal_id):
            raise ValueError("principal_id cannot contain whitespace")
        return principal_id

    @field_validator("sid")
    @classmethod
    def validate_sid(cls, sid: str | None) -> str | None:
        """Validate a Windows SID using a conservative shape check.

        Args:
            sid: SID string or None.

        Returns:
            The validated SID or None.

        Raises:
            ValueError: If the SID is malformed.
        """

        if sid is None:
            return None

        parts = sid.split("-")
        if len(parts) < 3 or parts[0] != "S":
            raise ValueError("sid must use Windows SID format")
        if not all(part.isdigit() for part in parts[1:]):
            raise ValueError("sid components after S must be numeric")
        return sid

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: list[str]) -> list[str]:
        """Normalize and de-duplicate tags.

        Args:
            tags: Raw tag strings.

        Returns:
            Lowercase, stripped, de-duplicated tags.
        """

        return _normalize_string_list(tags)

    @property
    def is_user(self) -> bool:
        """Return whether this principal is a user-like account.

        Returns:
            True for USER, SERVICE_ACCOUNT, and GMSA principals.
        """

        return self.type in {
            ADPrincipalType.USER,
            ADPrincipalType.SERVICE_ACCOUNT,
            ADPrincipalType.GMSA,
        }

    @property
    def is_computer(self) -> bool:
        """Return whether this principal is a computer account.

        Returns:
            True when type is COMPUTER.
        """

        return self.type == ADPrincipalType.COMPUTER

    @property
    def is_group(self) -> bool:
        """Return whether this principal is a group.

        Returns:
            True when type is GROUP.
        """

        return self.type == ADPrincipalType.GROUP

    @property
    def is_high_impact(self) -> bool:
        """Return whether this principal is high impact.

        Returns:
            True when high_value is true, owned is true, or risk_score is at least 8.0.
        """

        return self.high_value or self.owned or self.risk_score >= 8.0

    def mark_owned(self) -> ADPrincipal:
        """Return a copy of this principal marked owned.

        Returns:
            A new ADPrincipal with owned=True.
        """

        return self.model_copy(update={"owned": True})

    def mark_high_value(self) -> ADPrincipal:
        """Return a copy of this principal marked high value.

        Returns:
            A new ADPrincipal with high_value=True.
        """

        return self.model_copy(update={"high_value": True})

    def to_agent_dict(self) -> dict[str, Any]:
        """Return compact AD principal data for agent handoff.

        Returns:
            JSON-compatible principal metadata.
        """

        return {
            "principal_id": self.principal_id,
            "type": self.type.value,
            "name": self.name,
            "distinguished_name": self.distinguished_name,
            "domain": self.domain,
            "sid": self.sid,
            "object_guid": self.object_guid,
            "enabled": self.enabled,
            "high_value": self.high_value,
            "owned": self.owned,
            "risk_score": self.risk_score,
            "tags": self.tags,
        }

    def to_report_dict(self) -> dict[str, Any]:
        """Return report-safe AD principal data.

        Returns:
            JSON-compatible principal metadata for report exporters.
        """

        return self.to_agent_dict()


class ADRelationship(BaseModel):
    """Relationship between two Active Directory principals.

    Args:
        relationship_id: Stable SABER relationship identifier.
        type: AD relationship type.
        source: Source principal where the edge begins.
        target: Target principal where the edge ends.
        confidence: Confidence score from 0.0 to 1.0.
        evidence: Evidence records supporting this relationship.
        discovered_at: UTC timestamp when the relationship was recorded.
        metadata: Optional structured context from AD tools.

    Returns:
        A validated AD relationship object.
    """

    relationship_id: str = Field(default_factory=lambda: f"adr_{uuid4().hex}")
    type: ADRelationshipType
    source: ADPrincipal
    target: ADPrincipal
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("relationship_id")
    @classmethod
    def validate_relationship_id(cls, relationship_id: str) -> str:
        """Validate and normalize a relationship ID.

        Args:
            relationship_id: Raw relationship identifier.

        Returns:
            Validated relationship ID.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        normalized = relationship_id.strip()
        if not normalized:
            raise ValueError("relationship_id cannot be empty")
        if any(character.isspace() for character in normalized):
            raise ValueError("relationship_id cannot contain whitespace")
        return normalized

    @model_validator(mode="after")
    def validate_relationship_consistency(self) -> ADRelationship:
        """Validate cross-field relationship consistency.

        Returns:
            The validated ADRelationship object.

        Raises:
            ValueError: If source and target are the same principal for edge types
            that require two distinct principals.
        """

        self_edges_allowed = {
            ADRelationshipType.KERBEROASTABLE,
            ADRelationshipType.ASREP_ROASTABLE,
        }
        same_principal = self.source.principal_id == self.target.principal_id
        if same_principal and self.type not in self_edges_allowed:
            raise ValueError("relationship source and target must be different principals")
        return self

    @property
    def is_high_impact(self) -> bool:
        """Return whether this relationship is high impact.

        Returns:
            True for privilege-control relationships or high-value targets.
        """

        high_impact_relationships = {
            ADRelationshipType.ADMIN_TO,
            ADRelationshipType.ALLOWED_TO_DELEGATE,
            ADRelationshipType.OWNS,
            ADRelationshipType.GENERIC_ALL,
            ADRelationshipType.GENERIC_WRITE,
            ADRelationshipType.WRITE_DACL,
            ADRelationshipType.WRITE_OWNER,
            ADRelationshipType.FORCE_CHANGE_PASSWORD,
            ADRelationshipType.DCSYNC,
        }
        return self.type in high_impact_relationships or self.target.is_high_impact

    def to_agent_dict(self) -> dict[str, Any]:
        """Return compact AD relationship data for agent handoff.

        Returns:
            JSON-compatible relationship metadata.
        """

        return {
            "relationship_id": self.relationship_id,
            "type": self.type.value,
            "source": self.source.to_agent_dict(),
            "target": self.target.to_agent_dict(),
            "confidence": self.confidence,
            "evidence_refs": [record.evidence_id for record in self.evidence],
            "high_impact": self.is_high_impact,
            "discovered_at": self.discovered_at.isoformat(),
        }

    def to_report_dict(self) -> dict[str, Any]:
        """Return report-safe AD relationship data.

        Returns:
            JSON-compatible relationship metadata for report exporters.
        """

        return self.to_agent_dict()


def _normalize_string_list(values: list[str]) -> list[str]:
    """Normalize and de-duplicate string lists.

    Args:
        values: Raw string values.

    Returns:
        Lowercase, stripped, de-duplicated strings in original order.
    """

    seen: set[str] = set()
    normalized_values: list[str] = []

    for value in values:
        normalized = value.strip().lower().replace(" ", "_")
        if normalized and normalized not in seen:
            seen.add(normalized)
            normalized_values.append(normalized)

    return normalized_values