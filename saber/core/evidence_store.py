"""Evidence persistence helpers for SABER.

This module defines EvidenceStore, the core persistence layer for evidence files
and EvidenceRecord objects. Tool wrappers, sandbox executors, and mission
orchestrators use this module to save command output, structured tool output,
screenshots, imported files, and report artifacts in a consistent way.

EvidenceStore is intentionally not an execution layer. It does not run commands,
call Docker, decide scope, ask for approvals, call an LLM, or generate reports.
It only writes evidence safely under a configured root directory and returns
validated Pydantic evidence models.

Design goals:
    - Keep all evidence under one mission-specific root directory.
    - Prevent path traversal outside the evidence root.
    - Hash every persisted evidence file.
    - Keep enough command metadata to reproduce what produced the evidence.
    - Return EvidenceRecord objects that downstream reports and findings can cite.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from saber.models.evidence import (
    CommandMetadata,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceSensitivity,
    EvidenceSource,
    EvidenceStatus,
    EvidenceType,
)
from saber.models.target import Target


class EvidenceStoreError(RuntimeError):
    """Base exception for evidence store failures."""


class EvidencePathError(EvidenceStoreError):
    """Raised when a requested evidence path is unsafe or invalid."""


class EvidenceNotFoundError(EvidenceStoreError):
    """Raised when an evidence record or file cannot be found."""


class EvidenceStore:
    """Persist evidence files and create EvidenceRecord objects.

    Args:
        root_dir: Directory where all evidence files should be stored.

    Returns:
        EvidenceStore instance with an initialized evidence root.
    """

    def __init__(self, root_dir: str | Path) -> None:
        """Initialize the evidence store.

        Args:
            root_dir: Directory where evidence files will be stored.
        """

        self.root_dir = Path(root_dir).expanduser().resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, EvidenceRecord] = {}

    def save_text(
        self,
        title: str,
        content: str,
        relative_path: str | Path | None = None,
        evidence_type: EvidenceType = EvidenceType.TOOL_TEXT,
        source: EvidenceSource = EvidenceSource.TOOL_WRAPPER,
        target: Target | None = None,
        tool_name: str | None = None,
        command: CommandMetadata | None = None,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        status: EvidenceStatus = EvidenceStatus.COLLECTED,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Save text evidence and return an EvidenceRecord.

        Args:
            title: Human-readable evidence title.
            content: Text content to persist.
            relative_path: Optional path below the evidence root.
            evidence_type: Evidence type to assign.
            source: Evidence source to assign.
            target: Optional target associated with the evidence.
            tool_name: Optional tool name associated with the evidence.
            command: Optional command metadata.
            sensitivity: Evidence sensitivity level.
            status: Evidence status.
            metadata: Optional structured metadata.

        Returns:
            Created EvidenceRecord.
        """

        path = self._resolve_output_path(relative_path, suffix=".txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        return self._create_record(
            title=title,
            file_path=path,
            evidence_type=evidence_type,
            source=source,
            target=target,
            tool_name=tool_name,
            command=command,
            mime_type="text/plain",
            content_preview=self._preview_text(content),
            sensitivity=sensitivity,
            status=status,
            parsed_data=None,
            metadata=metadata,
        )

    def save_json(
        self,
        title: str,
        data: dict[str, Any] | list[Any],
        relative_path: str | Path | None = None,
        evidence_type: EvidenceType = EvidenceType.TOOL_JSON,
        source: EvidenceSource = EvidenceSource.TOOL_WRAPPER,
        target: Target | None = None,
        tool_name: str | None = None,
        command: CommandMetadata | None = None,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        status: EvidenceStatus = EvidenceStatus.PARSED,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Save JSON evidence and return an EvidenceRecord.

        Args:
            title: Human-readable evidence title.
            data: JSON-compatible data to persist.
            relative_path: Optional path below the evidence root.
            evidence_type: Evidence type to assign.
            source: Evidence source to assign.
            target: Optional target associated with the evidence.
            tool_name: Optional tool name associated with the evidence.
            command: Optional command metadata.
            sensitivity: Evidence sensitivity level.
            status: Evidence status.
            metadata: Optional structured metadata.

        Returns:
            Created EvidenceRecord.
        """

        path = self._resolve_output_path(relative_path, suffix=".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        json_text = json.dumps(data, indent=2, sort_keys=True, default=str)
        path.write_text(json_text + "\n", encoding="utf-8")

        parsed_data = data if isinstance(data, dict) else {"items": data}
        return self._create_record(
            title=title,
            file_path=path,
            evidence_type=evidence_type,
            source=source,
            target=target,
            tool_name=tool_name,
            command=command,
            mime_type="application/json",
            content_preview=self._preview_text(json_text),
            sensitivity=sensitivity,
            status=status,
            parsed_data=parsed_data,
            metadata=metadata,
        )

    def save_bytes(
        self,
        title: str,
        content: bytes,
        relative_path: str | Path | None = None,
        evidence_type: EvidenceType = EvidenceType.FILE,
        source: EvidenceSource = EvidenceSource.TOOL_WRAPPER,
        target: Target | None = None,
        tool_name: str | None = None,
        command: CommandMetadata | None = None,
        mime_type: str | None = None,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        status: EvidenceStatus = EvidenceStatus.COLLECTED,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Save binary evidence and return an EvidenceRecord.

        Args:
            title: Human-readable evidence title.
            content: Binary content to persist.
            relative_path: Optional path below the evidence root.
            evidence_type: Evidence type to assign.
            source: Evidence source to assign.
            target: Optional target associated with the evidence.
            tool_name: Optional tool name associated with the evidence.
            command: Optional command metadata.
            mime_type: Optional MIME type.
            sensitivity: Evidence sensitivity level.
            status: Evidence status.
            metadata: Optional structured metadata.

        Returns:
            Created EvidenceRecord.
        """

        path = self._resolve_output_path(relative_path, suffix=".bin")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

        return self._create_record(
            title=title,
            file_path=path,
            evidence_type=evidence_type,
            source=source,
            target=target,
            tool_name=tool_name,
            command=command,
            mime_type=mime_type,
            content_preview=None,
            sensitivity=sensitivity,
            status=status,
            parsed_data=None,
            metadata=metadata,
        )

    def save_command_output(
        self,
        title: str,
        stdout: str,
        stderr: str,
        command: CommandMetadata,
        relative_dir: str | Path | None = None,
        target: Target | None = None,
        tool_name: str | None = None,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Save combined command stdout/stderr as command-output evidence.

        Args:
            title: Human-readable evidence title.
            stdout: Captured command standard output.
            stderr: Captured command standard error.
            command: Command metadata describing execution.
            relative_dir: Optional directory below the evidence root.
            target: Optional target associated with the command.
            tool_name: Optional tool name associated with the command.
            sensitivity: Evidence sensitivity level.
            metadata: Optional structured metadata.

        Returns:
            Created EvidenceRecord.
        """

        command_slug = self._slugify(tool_name or command.tool_name or command.command[0])
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        base_dir = Path(relative_dir) if relative_dir is not None else Path("commands")
        relative_path = base_dir / f"{timestamp}_{command_slug}.txt"
        combined = self._format_command_output(stdout=stdout, stderr=stderr, command=command)

        return self.save_text(
            title=title,
            content=combined,
            relative_path=relative_path,
            evidence_type=EvidenceType.COMMAND_OUTPUT,
            source=EvidenceSource.TOOL_WRAPPER,
            target=target,
            tool_name=tool_name or command.tool_name,
            command=command,
            sensitivity=sensitivity,
            status=EvidenceStatus.COLLECTED,
            metadata=metadata,
        )

    def import_file(
        self,
        title: str,
        source_path: str | Path,
        relative_path: str | Path | None = None,
        evidence_type: EvidenceType = EvidenceType.FILE,
        source: EvidenceSource = EvidenceSource.IMPORTED,
        target: Target | None = None,
        tool_name: str | None = None,
        mime_type: str | None = None,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        status: EvidenceStatus = EvidenceStatus.COLLECTED,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Copy an existing file into the evidence root.

        Args:
            title: Human-readable evidence title.
            source_path: Existing file to import.
            relative_path: Optional destination path below the evidence root.
            evidence_type: Evidence type to assign.
            source: Evidence source to assign.
            target: Optional target associated with the evidence.
            tool_name: Optional tool name associated with the evidence.
            mime_type: Optional MIME type.
            sensitivity: Evidence sensitivity level.
            status: Evidence status.
            metadata: Optional structured metadata.

        Returns:
            Created EvidenceRecord.
        """

        source_file = Path(source_path).expanduser().resolve()
        if not source_file.is_file():
            raise EvidenceNotFoundError(f"Evidence source file does not exist: {source_file}")

        destination = self._resolve_output_path(
            relative_path,
            suffix=source_file.suffix or ".bin",
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination)

        return self._create_record(
            title=title,
            file_path=destination,
            evidence_type=evidence_type,
            source=source,
            target=target,
            tool_name=tool_name,
            command=None,
            mime_type=mime_type,
            content_preview=None,
            sensitivity=sensitivity,
            status=status,
            parsed_data=None,
            metadata=metadata,
        )

    def read_text(self, evidence_id: str) -> str:
        """Read a text evidence file by evidence ID.

        Args:
            evidence_id: Evidence record ID to read.

        Returns:
            Evidence file text content.
        """

        record = self.get_record(evidence_id)
        path = self._record_path(record)
        return path.read_text(encoding="utf-8")

    def read_bytes(self, evidence_id: str) -> bytes:
        """Read an evidence file as bytes by evidence ID.

        Args:
            evidence_id: Evidence record ID to read.

        Returns:
            Evidence file bytes.
        """

        record = self.get_record(evidence_id)
        path = self._record_path(record)
        return path.read_bytes()

    def get_record(self, evidence_id: str) -> EvidenceRecord:
        """Return an evidence record by ID.

        Args:
            evidence_id: Evidence record ID.

        Returns:
            Matching EvidenceRecord.
        """

        try:
            return self._records[evidence_id]
        except KeyError as exc:
            raise EvidenceNotFoundError(f"Evidence record not found: {evidence_id}") from exc

    def list_records(self) -> list[EvidenceRecord]:
        """Return all records known to this store.

        Returns:
            Evidence records in insertion order.
        """

        return list(self._records.values())

    def bundle(
        self,
        title: str,
        evidence_ids: list[str] | None = None,
        bundle_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceBundle:
        """Create an EvidenceBundle from known records.

        Args:
            title: Bundle title.
            evidence_ids: Optional record IDs to include. If omitted, all records are included.
            bundle_id: Optional bundle ID.
            metadata: Optional structured bundle metadata.

        Returns:
            EvidenceBundle containing selected records.
        """

        records = [self.get_record(evidence_id) for evidence_id in evidence_ids] if evidence_ids else self.list_records()
        return EvidenceBundle(
            bundle_id=bundle_id or f"bundle_{uuid4().hex}",
            title=title,
            records=records,
            metadata=metadata or {},
        )

    def exists(self, evidence_id: str) -> bool:
        """Return whether an evidence record exists in the store.

        Args:
            evidence_id: Evidence record ID.

        Returns:
            True when the record exists, else False.
        """

        return evidence_id in self._records

    def _create_record(
        self,
        title: str,
        file_path: Path,
        evidence_type: EvidenceType,
        source: EvidenceSource,
        target: Target | None,
        tool_name: str | None,
        command: CommandMetadata | None,
        mime_type: str | None,
        content_preview: str | None,
        sensitivity: EvidenceSensitivity,
        status: EvidenceStatus,
        parsed_data: dict[str, Any] | None,
        metadata: dict[str, Any] | None,
    ) -> EvidenceRecord:
        """Create, store, and return an EvidenceRecord.

        Args:
            title: Evidence title.
            file_path: Evidence file path.
            evidence_type: Evidence type.
            source: Evidence source.
            target: Optional evidence target.
            tool_name: Optional tool name.
            command: Optional command metadata.
            mime_type: Optional MIME type.
            content_preview: Optional content preview.
            sensitivity: Evidence sensitivity.
            status: Evidence status.
            parsed_data: Optional parsed data.
            metadata: Optional metadata.

        Returns:
            Created EvidenceRecord.
        """

        record = EvidenceRecord(
            evidence_id=f"ev_{uuid4().hex}",
            type=evidence_type,
            source=source,
            status=status,
            title=title,
            target=target,
            tool_name=tool_name,
            file_path=str(file_path.relative_to(self.root_dir)),
            mime_type=mime_type,
            sha256=self._sha256_file(file_path),
            size_bytes=file_path.stat().st_size,
            command=command,
            content_preview=content_preview,
            parsed_data=parsed_data,
            sensitivity=sensitivity,
            redacted=sensitivity == EvidenceSensitivity.SECRET,
            created_at=datetime.now(UTC),
            metadata=metadata or {},
        )
        self._records[record.evidence_id] = record
        return record

    def _resolve_output_path(self, relative_path: str | Path | None, suffix: str) -> Path:
        """Resolve and validate a destination path under the evidence root.

        Args:
            relative_path: Optional relative path requested by caller.
            suffix: File suffix to use for generated paths.

        Returns:
            Absolute destination path under root_dir.
        """

        if relative_path is None:
            relative_path = Path("evidence") / f"ev_{uuid4().hex}{suffix}"
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise EvidencePathError("Evidence paths must be relative to the evidence root.")
        if any(part == ".." for part in candidate.parts):
            raise EvidencePathError("Evidence paths cannot contain '..'.")

        resolved = (self.root_dir / candidate).resolve()
        if self.root_dir != resolved and self.root_dir not in resolved.parents:
            raise EvidencePathError("Evidence path escapes the evidence root.")
        return resolved

    def _record_path(self, record: EvidenceRecord) -> Path:
        """Return the absolute path for an evidence record.

        Args:
            record: EvidenceRecord with a file path.

        Returns:
            Absolute evidence path.
        """

        if not record.file_path:
            raise EvidenceNotFoundError(f"Evidence record has no file path: {record.evidence_id}")
        path = self._resolve_existing_path(record.file_path)
        if not path.is_file():
            raise EvidenceNotFoundError(f"Evidence file not found: {record.file_path}")
        return path

    def _resolve_existing_path(self, relative_path: str | Path) -> Path:
        """Resolve an existing evidence path safely under the root.

        Args:
            relative_path: Relative path stored on an EvidenceRecord.

        Returns:
            Absolute path under the evidence root.
        """

        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise EvidencePathError("Stored evidence path must be relative.")
        if any(part == ".." for part in candidate.parts):
            raise EvidencePathError("Stored evidence path cannot contain '..'.")
        resolved = (self.root_dir / candidate).resolve()
        if self.root_dir != resolved and self.root_dir not in resolved.parents:
            raise EvidencePathError("Stored evidence path escapes the evidence root.")
        return resolved

    @staticmethod
    def _sha256_file(path: Path) -> str:
        """Compute a file SHA-256 hash.

        Args:
            path: File path to hash.

        Returns:
            Lowercase SHA-256 hex digest.
        """

        digest = hashlib.sha256()
        with path.open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _preview_text(content: str, limit: int = 500) -> str:
        """Create a compact text preview.

        Args:
            content: Text content to preview.
            limit: Maximum preview length.

        Returns:
            Trimmed preview string.
        """

        stripped = content.strip()
        if len(stripped) <= limit:
            return stripped
        return stripped[: limit - 3].rstrip() + "..."

    @staticmethod
    def _format_command_output(stdout: str, stderr: str, command: CommandMetadata) -> str:
        """Format command output into one evidence document.

        Args:
            stdout: Captured standard output.
            stderr: Captured standard error.
            command: Command metadata.

        Returns:
            Combined command output text.
        """

        command_line = " ".join(command.command)
        return "\n".join(
            [
                f"$ {command_line}",
                f"return_code={command.return_code}",
                "",
                "[stdout]",
                stdout.rstrip(),
                "",
                "[stderr]",
                stderr.rstrip(),
                "",
            ]
        )

    @staticmethod
    def _slugify(value: str) -> str:
        """Create a filesystem-friendly slug.

        Args:
            value: String to slugify.

        Returns:
            Lowercase slug.
        """

        safe = "".join(character.lower() if character.isalnum() else "_" for character in value.strip())
        compact = "_".join(part for part in safe.split("_") if part)
        return compact or "evidence"