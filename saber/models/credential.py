

"""Credential models used across SABER.

This file defines safe data structures for credentials, hashes, tokens, keys,
certificates, and secret references discovered or imported during an authorized
SABER mission. These models are intentionally conservative: raw secret material
must never be exposed through report or agent serialization helpers.

Inputs:
    - Credential metadata from authorized tool wrappers.
    - Imported password/hash files from approved lab or client-provided sources.
    - Operator-provided secret references.
    - Evidence records that justify credential-related observations.

Outputs:
    - Normalized CredentialRecord, HashRecord, and SecretReference objects.
    - Report-safe and agent-safe dictionaries that exclude raw secret values.

Used by:
    - saber.tools.password.* wrappers
    - saber.tools.active_directory.* wrappers
    - saber.models.evidence
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
from saber.models.target import Target


class CredentialType(StrEnum):
    """Supported credential material types.

    Values:
        PASSWORD: Plaintext password or password reference.
        HASH: Password hash or hash reference.
        API_KEY: API key or API token.
        BEARER_TOKEN: Bearer token or session token.
        SSH_KEY: SSH private/public key material or reference.
        CERTIFICATE: Certificate, private key, or certificate bundle reference.
        NTLM_HASH: NTLM hash material or reference.
        KERBEROS_TICKET: Kerberos ticket or ticket cache reference.
        COOKIE: Web session cookie or cookie jar reference.
        OTHER: Any other credential-like secret.
    """

    PASSWORD = "password"
    HASH = "hash"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    COOKIE = "cookie"
    OTHER = "other"


class CredentialSource(StrEnum):
    """Source that produced or supplied credential material.

    Values:
        OPERATOR: Explicitly provided by the operator.
        CLIENT_PROVIDED: Provided by the client under rules of engagement.
        TOOL_OUTPUT: Produced by an authorized tool wrapper.
        IMPORTED_FILE: Imported from an approved file.
        LAB_GENERATED: Generated inside a controlled lab.
        UNKNOWN: Source is not known yet.
    """

    OPERATOR = "operator"
    CLIENT_PROVIDED = "client_provided"
    TOOL_OUTPUT = "tool_output"
    IMPORTED_FILE = "imported_file"
    LAB_GENERATED = "lab_generated"
    UNKNOWN = "unknown"


class CredentialSensitivity(StrEnum):
    """Sensitivity level for credential handling.

    Values:
        INTERNAL: Metadata only, no raw secret stored.
        CONFIDENTIAL: Sensitive credential metadata or redacted secret preview.
        SECRET: Raw credential material may exist in controlled storage.
    """

    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class CredentialStatus(StrEnum):
    """Validation or lifecycle status for credential material.

    Values:
        DISCOVERED: Credential-like material was discovered but not validated.
        IMPORTED: Credential was imported from an approved source.
        VALIDATED: Credential was validated in an authorized context.
        INVALID: Credential was tested and found invalid.
        EXPIRED: Credential appears expired.
        ROTATED: Credential has been rotated or invalidated after reporting.
        REVOKED: Credential was revoked.
        UNKNOWN: Status is unknown.
    """

    DISCOVERED = "discovered"
    IMPORTED = "imported"
    VALIDATED = "validated"
    INVALID = "invalid"
    EXPIRED = "expired"
    ROTATED = "rotated"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class HashType(StrEnum):
    """Supported hash formats tracked by SABER.

    Values:
        NTLM: Windows NTLM hash.
        LM: Legacy Windows LM hash.
        NETNTLMV1: NetNTLMv1 challenge/response hash.
        NETNTLMV2: NetNTLMv2 challenge/response hash.
        KERBEROS_ASREP: Kerberos AS-REP roast hash.
        KERBEROS_TGS: Kerberos TGS roast hash.
        BCRYPT: bcrypt password hash.
        SHA256_CRYPT: sha256crypt password hash.
        SHA512_CRYPT: sha512crypt password hash.
        UNKNOWN: Hash type is unknown.
    """

    NTLM = "ntlm"
    LM = "lm"
    NETNTLMV1 = "netntlmv1"
    NETNTLMV2 = "netntlmv2"
    KERBEROS_ASREP = "kerberos_asrep"
    KERBEROS_TGS = "kerberos_tgs"
    BCRYPT = "bcrypt"
    SHA256_CRYPT = "sha256crypt"
    SHA512_CRYPT = "sha512crypt"
    UNKNOWN = "unknown"


class SecretReference(BaseModel):
    """Reference to secret material stored outside normal reports.

    Args:
        secret_id: Stable secret reference ID.
        backend: Storage backend name, such as local_encrypted_file or vault.
        path: Backend-specific secret path or key.
        version: Optional backend-specific secret version.
        created_at: UTC timestamp when the reference was created.
        metadata: Optional structured metadata.

    Returns:
        A validated reference that can be stored safely without exposing raw secret values.
    """

    secret_id: str = Field(default_factory=lambda: f"secret_{uuid4().hex}")
    backend: str = "local_encrypted_file"
    path: str = Field(..., min_length=1)
    version: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("secret_id", "backend", "path", "version", mode="before")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize secret reference text fields.

        Args:
            value: Raw text or None.

        Returns:
            Stripped text, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("secret_id", "backend", "path")
    @classmethod
    def validate_required_reference_text(cls, value: str) -> str:
        """Validate required secret reference fields.

        Args:
            value: Normalized field value.

        Returns:
            The validated value.

        Raises:
            ValueError: If the value is empty or contains a null byte.
        """

        if not value:
            raise ValueError("secret reference fields cannot be empty")
        if "\x00" in value:
            raise ValueError("secret reference fields cannot contain null bytes")
        return value

    def to_reference(self) -> dict[str, str | None]:
        """Return a safe secret reference dictionary.

        Returns:
            JSON-compatible metadata without raw secret material.
        """

        return {
            "secret_id": self.secret_id,
            "backend": self.backend,
            "path": self.path,
            "version": self.version,
        }


class HashRecord(BaseModel):
    """Metadata for password hashes or hash references.

    Args:
        hash_id: Stable hash record identifier.
        hash_type: Hash format.
        username: Optional account username associated with the hash.
        domain: Optional account domain or realm.
        redacted_hash: Redacted hash preview safe for reports.
        secret_ref: Optional pointer to raw hash material in controlled storage.
        cracked: Whether the hash has been cracked in an authorized context.
        cracked_secret_ref: Optional pointer to cracked secret material.
        evidence: Evidence records supporting this hash observation.
        created_at: UTC timestamp when the hash record was created.
        metadata: Optional structured metadata.

    Returns:
        A validated hash metadata object that does not expose raw hash material.
    """

    hash_id: str = Field(default_factory=lambda: f"hash_{uuid4().hex}")
    hash_type: HashType = HashType.UNKNOWN
    username: str | None = None
    domain: str | None = None
    redacted_hash: str | None = None
    secret_ref: SecretReference | None = None
    cracked: bool = False
    cracked_secret_ref: SecretReference | None = None
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hash_id", "username", "domain", "redacted_hash", mode="before")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize hash text fields.

        Args:
            value: Raw text or None.

        Returns:
            Stripped text, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("hash_id")
    @classmethod
    def validate_hash_id(cls, hash_id: str) -> str:
        """Validate and normalize a hash ID.

        Args:
            hash_id: Raw hash identifier.

        Returns:
            Validated hash identifier.

        Raises:
            ValueError: If the hash ID is empty or contains whitespace.
        """

        if not hash_id:
            raise ValueError("hash_id cannot be empty")
        if any(character.isspace() for character in hash_id):
            raise ValueError("hash_id cannot contain whitespace")
        return hash_id

    @model_validator(mode="after")
    def validate_cracked_reference(self) -> HashRecord:
        """Validate cracked hash reference consistency.

        Returns:
            The validated HashRecord object.

        Raises:
            ValueError: If cracked=True but no cracked secret reference exists.
        """

        if self.cracked and self.cracked_secret_ref is None:
            raise ValueError("cracked hashes require cracked_secret_ref")
        return self

    def mark_cracked(self, cracked_secret_ref: SecretReference) -> HashRecord:
        """Return a copy of this hash marked cracked.

        Args:
            cracked_secret_ref: Reference to cracked secret material.

        Returns:
            A new HashRecord with cracked=True.
        """

        return self.model_copy(
            update={"cracked": True, "cracked_secret_ref": cracked_secret_ref}
        )

    def to_reference(self) -> dict[str, Any]:
        """Return a safe hash reference for findings and reports.

        Returns:
            JSON-compatible hash metadata without raw hash or plaintext material.
        """

        return {
            "hash_id": self.hash_id,
            "hash_type": self.hash_type.value,
            "username": self.username,
            "domain": self.domain,
            "redacted_hash": self.redacted_hash,
            "secret_ref": self.secret_ref.to_reference() if self.secret_ref else None,
            "cracked": self.cracked,
            "cracked_secret_ref": (
                self.cracked_secret_ref.to_reference() if self.cracked_secret_ref else None
            ),
            "evidence_refs": [record.evidence_id for record in self.evidence],
        }


class CredentialRecord(BaseModel):
    """Canonical SABER credential record.

    Args:
        credential_id: Stable credential identifier.
        type: Credential material type.
        source: Source that produced or supplied the credential.
        status: Validation or lifecycle state.
        sensitivity: Credential sensitivity level.
        username: Optional username associated with the credential.
        domain: Optional account domain, realm, or tenant.
        service: Optional service or protocol where the credential applies.
        target: Optional target where the credential was observed or applies.
        redacted_preview: Report-safe preview such as `user:<redacted>`.
        secret_ref: Optional pointer to raw secret material in controlled storage.
        hash_record: Optional associated hash metadata.
        evidence: Evidence records supporting the credential observation.
        discovered_at: UTC timestamp when the credential was recorded.
        last_validated_at: Optional UTC timestamp for validation.
        metadata: Optional structured metadata.

    Returns:
        A validated credential record that never exposes raw secret material through helpers.
    """

    credential_id: str = Field(default_factory=lambda: f"cred_{uuid4().hex}")
    type: CredentialType
    source: CredentialSource = CredentialSource.UNKNOWN
    status: CredentialStatus = CredentialStatus.DISCOVERED
    sensitivity: CredentialSensitivity = CredentialSensitivity.CONFIDENTIAL
    username: str | None = None
    domain: str | None = None
    service: str | None = None
    target: Target | None = None
    redacted_preview: str | None = None
    secret_ref: SecretReference | None = None
    hash_record: HashRecord | None = None
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_validated_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "credential_id",
        "username",
        "domain",
        "service",
        "redacted_preview",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize credential text fields.

        Args:
            value: Raw text or None.

        Returns:
            Stripped text, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("credential_id")
    @classmethod
    def validate_credential_id(cls, credential_id: str) -> str:
        """Validate and normalize a credential ID.

        Args:
            credential_id: Raw credential identifier.

        Returns:
            Validated credential identifier.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        if not credential_id:
            raise ValueError("credential_id cannot be empty")
        if any(character.isspace() for character in credential_id):
            raise ValueError("credential_id cannot contain whitespace")
        return credential_id

    @model_validator(mode="after")
    def validate_credential_consistency(self) -> CredentialRecord:
        """Validate credential consistency and safe handling rules.

        Returns:
            The validated CredentialRecord object.

        Raises:
            ValueError: If a secret credential has neither redacted preview nor secret reference,
            or if validation timestamps are inconsistent.
        """

        if self.sensitivity == CredentialSensitivity.SECRET:
            if self.secret_ref is None and self.redacted_preview is None:
                raise ValueError("secret credentials require secret_ref or redacted_preview")

        if self.status == CredentialStatus.VALIDATED and self.last_validated_at is None:
            raise ValueError("validated credentials require last_validated_at")

        if self.last_validated_at and self.last_validated_at < self.discovered_at:
            raise ValueError("last_validated_at cannot be earlier than discovered_at")

        return self

    @property
    def has_secret_reference(self) -> bool:
        """Return whether this credential points to controlled secret storage.

        Returns:
            True when secret_ref exists.
        """

        return self.secret_ref is not None

    @property
    def is_validated(self) -> bool:
        """Return whether this credential has been validated.

        Returns:
            True when status is VALIDATED.
        """

        return self.status == CredentialStatus.VALIDATED

    @property
    def is_sensitive(self) -> bool:
        """Return whether this credential requires sensitive handling.

        Returns:
            True for confidential or secret credentials.
        """

        return self.sensitivity in {
            CredentialSensitivity.CONFIDENTIAL,
            CredentialSensitivity.SECRET,
        }

    def mark_validated(self, validated_at: datetime | None = None) -> CredentialRecord:
        """Return a copy of this credential marked validated.

        Args:
            validated_at: Optional validation timestamp. Defaults to current UTC time.

        Returns:
            A new CredentialRecord with status VALIDATED.
        """

        return self.model_copy(
            update={
                "status": CredentialStatus.VALIDATED,
                "last_validated_at": validated_at or datetime.now(UTC),
            }
        )

    def mark_invalid(self) -> CredentialRecord:
        """Return a copy of this credential marked invalid.

        Returns:
            A new CredentialRecord with status INVALID.
        """

        return self.model_copy(update={"status": CredentialStatus.INVALID})

    def mark_rotated(self) -> CredentialRecord:
        """Return a copy of this credential marked rotated.

        Returns:
            A new CredentialRecord with status ROTATED.
        """

        return self.model_copy(update={"status": CredentialStatus.ROTATED})

    def mark_secret(self, secret_ref: SecretReference | None = None) -> CredentialRecord:
        """Return a copy of this credential marked secret.

        Args:
            secret_ref: Optional controlled storage reference to attach.

        Returns:
            A new CredentialRecord with sensitivity SECRET.
        """

        update: dict[str, Any] = {"sensitivity": CredentialSensitivity.SECRET}
        if secret_ref is not None:
            update["secret_ref"] = secret_ref
        return self.model_copy(update=update)

    def to_reference(self) -> dict[str, Any]:
        """Return a compact credential reference for findings and reports.

        Returns:
            JSON-compatible credential metadata without raw secret material.
        """

        return {
            "credential_id": self.credential_id,
            "type": self.type.value,
            "source": self.source.value,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "username": self.username,
            "domain": self.domain,
            "service": self.service,
            "target": self.target.to_agent_dict() if self.target else None,
            "redacted_preview": self.redacted_preview,
            "secret_ref": self.secret_ref.to_reference() if self.secret_ref else None,
            "hash_record": self.hash_record.to_reference() if self.hash_record else None,
            "evidence_refs": [record.evidence_id for record in self.evidence],
            "last_validated_at": (
                self.last_validated_at.isoformat() if self.last_validated_at else None
            ),
        }

    def to_agent_dict(self) -> dict[str, Any]:
        """Return compact credential data safe for agent handoff.

        Returns:
            JSON-compatible credential context without raw secret values.
        """

        return self.to_reference()

    def to_report_dict(self) -> dict[str, Any]:
        """Return compact credential data safe for reports.

        Returns:
            JSON-compatible credential context without raw secret values.
        """

        return self.to_reference()