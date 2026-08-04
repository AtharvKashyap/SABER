"""strings wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

_ENCODINGS = ("s", "S", "b", "l", "B", "L")

_FILE_PATH_ARG = ArgSpec(
    "file_path",
    "str",
    required=True,
    description="Path to the file to extract strings from, inside the sandbox.",
)
_MIN_LENGTH_ARG = ArgSpec(
    "min_length",
    "int",
    required=False,
    default=4,
    example=6,
    description="Minimum string length to report (strings -n).",
)

CONTRACT = ToolContract(
    tool_name="strings",
    category="reverse_engineering",
    phase="recon",
    description=(
        "Extract printable strings from a binary or blob. Often the fastest route to "
        "hardcoded credentials, connection strings, embedded URLs, and CTF flags."
    ),
    parser="strings",
    actions=(
        ActionContract(
            action="extract",
            description="Extract ASCII strings, optionally in a specific encoding.",
            args=(
                _FILE_PATH_ARG,
                _MIN_LENGTH_ARG,
                ArgSpec(
                    "encoding",
                    "enum",
                    required=False,
                    choices=_ENCODINGS,
                    description="strings -e encoding (s/S single byte, b/l 16-bit, B/L 32-bit).",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note", "loot", "flag"),
            example_args={"file_path": "/opt/lab/vulnbin", "min_length": 6},
        ),
        ActionContract(
            action="unicode",
            description=(
                "Extract 16-bit little-endian strings (-e l). Use on Windows binaries, "
                "whose strings are usually UTF-16 and invisible to a plain scan."
            ),
            args=(_FILE_PATH_ARG, _MIN_LENGTH_ARG),
            risk="low",
            requires_approval=False,
            emits_kinds=("note", "loot", "flag"),
            example_args={"file_path": "/opt/lab/agent.exe"},
        ),
        ActionContract(
            action="grep",
            description="Extract strings and keep only those matching a pattern.",
            args=(
                _FILE_PATH_ARG,
                _MIN_LENGTH_ARG,
                ArgSpec(
                    "pattern",
                    "str",
                    required=True,
                    description="Case-insensitive pattern to filter on, e.g. password.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note", "loot", "flag"),
            example_args={"file_path": "/opt/lab/vulnbin", "pattern": "password"},
        ),
    ),
)


class StringsWrapper(BaseToolWrapper):
    """Wrapper for strings extraction workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize strings wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="strings",
                image="saber/strings:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="StringsWrapper",
                default_timeout_seconds=300,
                default_metadata={"tool_family": "reverse_engineering", "tool": "strings"},
            ),
        )

    def extract(
        self,
        target: Target,
        session: MissionSession,
        file_path: str,
        min_length: int = 4,
        encoding: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Extract printable strings."""

        return self.run(
            target=target,
            session=session,
            action="extract",
            file_path=file_path,
            min_length=min_length,
            encoding=encoding,
            metadata=metadata,
        )

    def unicode(
        self,
        target: Target,
        session: MissionSession,
        file_path: str,
        min_length: int = 4,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Extract little-endian Unicode strings."""

        return self.run(
            target=target,
            session=session,
            action="unicode",
            file_path=file_path,
            min_length=min_length,
            metadata=metadata,
        )

    def grep(
        self,
        target: Target,
        session: MissionSession,
        file_path: str,
        pattern: str,
        min_length: int = 4,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Extract strings and grep for a pattern."""

        return self.run(
            target=target,
            session=session,
            action="grep",
            file_path=file_path,
            pattern=pattern,
            min_length=min_length,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a strings ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        file_path = self._required_string(kwargs, "file_path")
        min_length = self._positive_int(kwargs.get("min_length", 4), "min_length")
        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            "file_path": file_path,
            "min_length": min_length,
            **(kwargs.get("metadata") or {}),
        }

        if action == "extract":
            command = ["strings", "-n", str(min_length)]
            encoding = kwargs.get("encoding")
            if encoding:
                encoding = self._validate_encoding(encoding)
                command.extend(["-e", encoding])
            command.append(file_path)

            return ToolCommand(
                command=command,
                action="extract",
                evidence_title=f"strings extract: {file_path}",
                evidence_relative_dir="reverse_engineering/strings/extract",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "encoding": encoding},
            )

        if action == "unicode":
            return ToolCommand(
                command=["strings", "-n", str(min_length), "-e", "l", file_path],
                action="unicode",
                evidence_title=f"strings unicode: {file_path}",
                evidence_relative_dir="reverse_engineering/strings/unicode",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "encoding": "l"},
            )

        if action == "grep":
            pattern = self._required_string(kwargs, "pattern")
            return ToolCommand(
                command=["bash", "-lc", f"strings -n {min_length} {file_path} | grep -i -- {pattern}"],
                action="grep",
                evidence_title=f"strings grep: {file_path}",
                evidence_relative_dir="reverse_engineering/strings/grep",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "pattern": pattern},
            )

        raise ValueError(f"Unsupported strings action: {action}")

    @staticmethod
    def _validate_encoding(value: Any) -> str:
        """Validate strings encoding."""

        encoding = str(value).strip()
        if encoding not in {"s", "S", "b", "l", "B", "L"}:
            raise ValueError("encoding must be one of: s, S, b, l, B, L")
        return encoding

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _positive_int(value: Any, key: str) -> int:
        """Validate a positive integer."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return parsed
