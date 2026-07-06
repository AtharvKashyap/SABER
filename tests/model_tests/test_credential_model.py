

"""Tests for SABER credential models.

This file verifies that `saber.models.credential` safely models credentials,
hashes, tokens, and secret references without exposing raw secret material through
report or agent serialization helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from saber.models.credential import (
    CredentialRecord,
    CredentialSensitivity,
    CredentialSource,
    CredentialStatus,
    CredentialType,
    HashRecord,
    HashType,
    SecretReference,
)
from saber.models.evidence import EvidenceRecord, EvidenceType
from saber.models.target import Target, TargetType


def make_target() -> Target:
    """Create a reusable target for credential tests.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.HOST, value="dc01.internal")


def make_evidence(evidence_id: str = "ev_cred") -> EvidenceRecord:
    """Create a reusable evidence record for credential tests.

    Args:
        evidence_id: Evidence identifier to assign.

    Returns:
        A validated EvidenceRecord object.
    """

    return EvidenceRecord(
        evidence_id=evidence_id,
        type=EvidenceType.TOOL_TEXT,
        title="Credential observation",
        file_path="evidence/credentials.txt",
    )


def make_secret_ref(secret_id: str = "secret_1") -> SecretReference:
    """Create a reusable secret reference for credential tests.

    Args:
        secret_id: Secret reference identifier to assign.

    Returns:
        A validated SecretReference object.
    """

    return SecretReference(
        secret_id=secret_id,
        backend="local_encrypted_file",
        path="sessions/demo/secrets/secret_1.enc",
        version="1",
    )


def make_hash_record(hash_id: str = "hash_1") -> HashRecord:
    """Create a reusable hash record for credential tests.

    Args:
        hash_id: Hash record identifier to assign.

    Returns:
        A validated HashRecord object.
    """

    return HashRecord(
        hash_id=hash_id,
        hash_type=HashType.NTLM,
        username=" administrator ",
        domain=" INTERNAL ",
        redacted_hash="8846f7ea...<redacted>",
        secret_ref=make_secret_ref("secret_hash"),
        evidence=[make_evidence("ev_hash")],
    )


def make_credential(credential_id: str = "cred_1") -> CredentialRecord:
    """Create a reusable credential record for tests.

    Args:
        credential_id: Credential identifier to assign.

    Returns:
        A validated CredentialRecord object.
    """

    return CredentialRecord(
        credential_id=credential_id,
        type=CredentialType.PASSWORD,
        source=CredentialSource.CLIENT_PROVIDED,
        status=CredentialStatus.IMPORTED,
        sensitivity=CredentialSensitivity.CONFIDENTIAL,
        username=" administrator ",
        domain=" INTERNAL ",
        service=" ssh ",
        target=make_target(),
        redacted_preview="administrator:<redacted>",
        secret_ref=make_secret_ref(),
        evidence=[make_evidence()],
    )


class TestSecretReference:
    """Validate SecretReference behavior."""

    def test_valid_secret_reference(self) -> None:
        """A valid secret reference should normalize text fields."""

        reference = SecretReference(
            secret_id=" secret_abc ",
            backend=" vault ",
            path=" secret/data/saber/demo ",
            version=" 3 ",
        )

        assert reference.secret_id == "secret_abc"
        assert reference.backend == "vault"
        assert reference.path == "secret/data/saber/demo"
        assert reference.version == "3"
        assert reference.created_at.tzinfo == UTC

    def test_auto_generated_secret_id_has_expected_prefix(self) -> None:
        """Secret IDs should be generated when omitted."""

        reference = SecretReference(path="sessions/demo/secrets/value.enc")

        assert reference.secret_id.startswith("secret_")
        assert len(reference.secret_id) > len("secret_")

    @pytest.mark.parametrize(
        ("field_name", "field_value"),
        [
            ("secret_id", ""),
            ("secret_id", "   "),
            ("backend", ""),
            ("backend", "   "),
            ("path", ""),
            ("path", "   "),
            ("path", "bad\x00path"),
        ],
    )
    def test_invalid_required_reference_fields_raise_error(
        self,
        field_name: str,
        field_value: str,
    ) -> None:
        """Required secret reference fields should reject empty or unsafe values."""

        data = {
            "secret_id": "secret_1",
            "backend": "local_encrypted_file",
            "path": "sessions/demo/secrets/value.enc",
        }
        data[field_name] = field_value

        with pytest.raises(ValueError):
            SecretReference(**data)

    def test_to_reference_excludes_secret_material(self) -> None:
        """Secret references should serialize only storage metadata."""

        reference = make_secret_ref()

        assert reference.to_reference() == {
            "secret_id": "secret_1",
            "backend": "local_encrypted_file",
            "path": "sessions/demo/secrets/secret_1.enc",
            "version": "1",
        }


class TestHashRecord:
    """Validate HashRecord behavior."""

    def test_valid_hash_record(self) -> None:
        """A hash record should normalize text fields and keep safe references."""

        record = make_hash_record()

        assert record.hash_id == "hash_1"
        assert record.hash_type == HashType.NTLM
        assert record.username == "administrator"
        assert record.domain == "INTERNAL"
        assert record.redacted_hash == "8846f7ea...<redacted>"
        assert record.secret_ref is not None
        assert record.evidence[0].evidence_id == "ev_hash"
        assert record.created_at.tzinfo == UTC

    def test_auto_generated_hash_id_has_expected_prefix(self) -> None:
        """Hash IDs should be generated when omitted."""

        record = HashRecord()

        assert record.hash_id.startswith("hash_")
        assert len(record.hash_id) > len("hash_")

    @pytest.mark.parametrize("hash_id", ["", "   ", "hash 1"])
    def test_invalid_hash_id_raises_error(self, hash_id: str) -> None:
        """Empty or whitespace-containing hash IDs should be rejected."""

        with pytest.raises(ValueError):
            HashRecord(hash_id=hash_id)

    def test_cracked_hash_requires_cracked_secret_reference(self) -> None:
        """A cracked hash should require a reference to cracked secret material."""

        with pytest.raises(ValueError):
            HashRecord(hash_id="hash_cracked", cracked=True)

    def test_mark_cracked_returns_updated_copy(self) -> None:
        """mark_cracked should return a copied hash record with cracked metadata."""

        record = make_hash_record()
        cracked_ref = make_secret_ref("secret_cracked")

        updated = record.mark_cracked(cracked_ref)

        assert record.cracked is False
        assert record.cracked_secret_ref is None
        assert updated.cracked is True
        assert updated.cracked_secret_ref == cracked_ref

    def test_to_reference_excludes_raw_hash_and_plaintext(self) -> None:
        """Hash references should expose only safe metadata and storage references."""

        record = make_hash_record()
        reference = record.to_reference()

        assert reference["hash_id"] == "hash_1"
        assert reference["hash_type"] == "ntlm"
        assert reference["username"] == "administrator"
        assert reference["domain"] == "INTERNAL"
        assert reference["redacted_hash"] == "8846f7ea...<redacted>"
        assert reference["secret_ref"] == make_secret_ref("secret_hash").to_reference()
        assert reference["cracked"] is False
        assert reference["cracked_secret_ref"] is None
        assert reference["evidence_refs"] == ["ev_hash"]
        assert "password" not in reference
        assert "plaintext" not in reference
        assert "raw_hash" not in reference


class TestCredentialRecordCreation:
    """Validate CredentialRecord construction and normalization."""

    def test_valid_credential_record(self) -> None:
        """A normal credential record should be valid and normalize text fields."""

        credential = make_credential()

        assert credential.credential_id == "cred_1"
        assert credential.type == CredentialType.PASSWORD
        assert credential.source == CredentialSource.CLIENT_PROVIDED
        assert credential.status == CredentialStatus.IMPORTED
        assert credential.sensitivity == CredentialSensitivity.CONFIDENTIAL
        assert credential.username == "administrator"
        assert credential.domain == "INTERNAL"
        assert credential.service == "ssh"
        assert credential.target == make_target()
        assert credential.redacted_preview == "administrator:<redacted>"
        assert credential.secret_ref is not None
        assert credential.secret_ref.to_reference() == make_secret_ref().to_reference()
        assert credential.evidence[0].evidence_id == "ev_cred"
        assert credential.discovered_at.tzinfo == UTC

    def test_auto_generated_credential_id_has_expected_prefix(self) -> None:
        """Credential IDs should be generated when omitted."""

        credential = CredentialRecord(type=CredentialType.API_KEY)

        assert credential.credential_id.startswith("cred_")
        assert len(credential.credential_id) > len("cred_")

    def test_empty_optional_text_becomes_none(self) -> None:
        """Optional credential text fields should normalize empty strings to None."""

        credential = CredentialRecord(
            type=CredentialType.API_KEY,
            username="   ",
            domain="   ",
            service="   ",
            redacted_preview="   ",
        )

        assert credential.username is None
        assert credential.domain is None
        assert credential.service is None
        assert credential.redacted_preview is None

    def test_credential_can_reference_hash_record(self) -> None:
        """Credential records should support associated hash metadata."""

        hash_record = make_hash_record()
        credential = CredentialRecord(
            type=CredentialType.NTLM_HASH,
            username="administrator",
            hash_record=hash_record,
            redacted_preview="administrator:8846f7ea...<redacted>",
        )

        assert credential.hash_record == hash_record
        assert credential.to_reference()["hash_record"] == hash_record.to_reference()


class TestCredentialRecordValidation:
    """Validate credential consistency and safety rules."""

    @pytest.mark.parametrize("credential_id", ["", "   ", "cred 1"])
    def test_invalid_credential_id_raises_error(self, credential_id: str) -> None:
        """Empty or whitespace-containing credential IDs should be rejected."""

        with pytest.raises(ValueError):
            CredentialRecord(credential_id=credential_id, type=CredentialType.PASSWORD)

    def test_secret_credential_requires_secret_ref_or_redacted_preview(self) -> None:
        """Secret credentials should require a secret reference or redacted preview."""

        with pytest.raises(ValueError):
            CredentialRecord(
                type=CredentialType.PASSWORD,
                sensitivity=CredentialSensitivity.SECRET,
            )

    def test_secret_credential_with_secret_reference_is_valid(self) -> None:
        """Secret credentials should be valid with a controlled secret reference."""

        credential = CredentialRecord(
            type=CredentialType.PASSWORD,
            sensitivity=CredentialSensitivity.SECRET,
            secret_ref=make_secret_ref(),
        )

        assert credential.sensitivity == CredentialSensitivity.SECRET
        assert credential.secret_ref is not None
        assert credential.secret_ref.to_reference() == make_secret_ref().to_reference()

    def test_secret_credential_with_redacted_preview_is_valid(self) -> None:
        """Secret credentials should be valid with a redacted preview."""

        credential = CredentialRecord(
            type=CredentialType.PASSWORD,
            sensitivity=CredentialSensitivity.SECRET,
            redacted_preview="administrator:<redacted>",
        )

        assert credential.sensitivity == CredentialSensitivity.SECRET
        assert credential.redacted_preview == "administrator:<redacted>"

    def test_validated_credential_requires_validation_timestamp(self) -> None:
        """Validated credentials should require last_validated_at."""

        with pytest.raises(ValueError):
            CredentialRecord(
                type=CredentialType.PASSWORD,
                status=CredentialStatus.VALIDATED,
                redacted_preview="administrator:<redacted>",
            )

    def test_last_validated_before_discovered_raises_error(self) -> None:
        """Validation timestamps should not predate discovery timestamps."""

        discovered_at = datetime.now(UTC)
        last_validated_at = discovered_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            CredentialRecord(
                type=CredentialType.PASSWORD,
                discovered_at=discovered_at,
                last_validated_at=last_validated_at,
                redacted_preview="administrator:<redacted>",
            )


class TestCredentialRecordHelpers:
    """Validate credential helper properties and copy methods."""

    def test_helper_properties(self) -> None:
        """Credential helper properties should reflect record state."""

        credential = make_credential()
        validated = credential.mark_validated()
        internal = CredentialRecord(
            type=CredentialType.OTHER,
            sensitivity=CredentialSensitivity.INTERNAL,
        )

        assert credential.has_secret_reference
        assert credential.is_sensitive
        assert not credential.is_validated
        assert validated.is_validated
        assert not internal.is_sensitive

    def test_mark_validated_returns_updated_copy(self) -> None:
        """mark_validated should set status and validation timestamp."""

        credential = make_credential()
        validated_at = datetime.now(UTC)

        updated = credential.mark_validated(validated_at)

        assert credential.status == CredentialStatus.IMPORTED
        assert credential.last_validated_at is None
        assert updated.status == CredentialStatus.VALIDATED
        assert updated.last_validated_at == validated_at

    def test_mark_invalid_returns_updated_copy(self) -> None:
        """mark_invalid should return a copied credential marked invalid."""

        credential = make_credential()
        updated = credential.mark_invalid()

        assert credential.status == CredentialStatus.IMPORTED
        assert updated.status == CredentialStatus.INVALID

    def test_mark_rotated_returns_updated_copy(self) -> None:
        """mark_rotated should return a copied credential marked rotated."""

        credential = make_credential()
        updated = credential.mark_rotated()

        assert credential.status == CredentialStatus.IMPORTED
        assert updated.status == CredentialStatus.ROTATED

    def test_mark_secret_returns_updated_copy(self) -> None:
        """mark_secret should return a copied credential marked secret."""

        credential = make_credential()
        secret_ref = make_secret_ref("secret_new")

        updated = credential.mark_secret(secret_ref)

        assert credential.sensitivity == CredentialSensitivity.CONFIDENTIAL
        assert updated.sensitivity == CredentialSensitivity.SECRET
        assert updated.secret_ref == secret_ref


class TestCredentialSerialization:
    """Validate safe credential serialization."""

    def test_to_reference_excludes_raw_secret_material(self) -> None:
        """Credential references should expose metadata, not raw secrets."""

        credential = make_credential().mark_validated(datetime(2026, 1, 1, tzinfo=UTC))
        reference = credential.to_reference()

        assert reference["credential_id"] == "cred_1"
        assert reference["type"] == "password"
        assert reference["source"] == "client_provided"
        assert reference["status"] == "validated"
        assert reference["sensitivity"] == "confidential"
        assert reference["username"] == "administrator"
        assert reference["domain"] == "INTERNAL"
        assert reference["service"] == "ssh"
        assert reference["target"] == {"type": "host", "value": "dc01.internal"}
        assert reference["redacted_preview"] == "administrator:<redacted>"
        assert reference["secret_ref"] == make_secret_ref().to_reference()
        assert reference["hash_record"] is None
        assert reference["evidence_refs"] == ["ev_cred"]
        assert reference["last_validated_at"] == "2026-01-01T00:00:00+00:00"
        assert "password" not in reference.keys() - {"type"}
        assert "raw_secret" not in reference
        assert "plaintext" not in reference
        assert "secret_value" not in reference

    def test_to_agent_dict_matches_safe_reference(self) -> None:
        """Agent serialization should use the same safe reference shape."""

        credential = make_credential()

        assert credential.to_agent_dict() == credential.to_reference()

    def test_to_report_dict_matches_safe_reference(self) -> None:
        """Report serialization should use the same safe reference shape."""

        credential = make_credential()

        assert credential.to_report_dict() == credential.to_reference()

    def test_serialization_includes_hash_reference_without_raw_material(self) -> None:
        """Credential serialization should include safe hash metadata only."""

        hash_record = make_hash_record()
        credential = CredentialRecord(
            credential_id="cred_hash",
            type=CredentialType.NTLM_HASH,
            username="administrator",
            hash_record=hash_record,
            redacted_preview="administrator:8846f7ea...<redacted>",
        )

        reference = credential.to_reference()

        assert reference["credential_id"] == "cred_hash"
        assert reference["hash_record"] == hash_record.to_reference()
        assert "raw_hash" not in reference["hash_record"]
        assert "plaintext" not in reference["hash_record"]