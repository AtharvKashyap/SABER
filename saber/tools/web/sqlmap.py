"""sqlmap wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

CONTRACT = ToolContract(
    tool_name="sqlmap",
    category="web",
    phase="exploitation",
    description="Automated SQL injection detection and exploitation.",
    parser="sqlmap",
    actions=(
        ActionContract(
            action="injection_test",
            description="Test a URL for SQL injection (sqlmap --risk --level --batch).",
            args=(
                ArgSpec(
                    "url",
                    "str",
                    required=True,
                    description="Target URL with injectable parameter.",
                ),
                ArgSpec(
                    "risk",
                    "int",
                    required=False,
                    default=1,
                    example=1,
                    description="sqlmap --risk (1-3).",
                ),
                ArgSpec(
                    "level",
                    "int",
                    required=False,
                    default=1,
                    example=1,
                    description="sqlmap --level (1-5).",
                ),
                ArgSpec(
                    "batch",
                    "bool",
                    required=False,
                    default=True,
                    description="Run non-interactively (--batch).",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("vuln", "note"),
            example_args={"url": "https://127.0.0.1/item?id=1"},
        ),
        ActionContract(
            action="test_request",
            description=(
                "Test a saved raw HTTP request file for SQL injection (sqlmap -r). Use when the "
                "injectable parameter is in a POST body, header, or cookie rather than the URL."
            ),
            args=(
                ArgSpec(
                    "request_file",
                    "str",
                    required=True,
                    description="Path to a raw HTTP request file inside the sandbox.",
                ),
                ArgSpec("risk", "int", required=False, default=1, description="--risk (1-3)."),
                ArgSpec("level", "int", required=False, default=1, description="--level (1-5)."),
                ArgSpec("batch", "bool", required=False, default=True),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("vuln", "note"),
            example_args={"request_file": "/tmp/request.txt"},
        ),
        ActionContract(
            action="dump_schema",
            description=(
                "Enumerate the database schema through a confirmed injection (sqlmap --schema). "
                "Run only after injection_test has confirmed the vulnerability."
            ),
            args=(
                ArgSpec(
                    "url",
                    "str",
                    required=True,
                    description="Target URL with the confirmed injectable parameter.",
                ),
                ArgSpec("batch", "bool", required=False, default=True),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("vuln", "note"),
            example_args={"url": "https://127.0.0.1/item?id=1"},
        ),
    ),
)


class SqlmapWrapper(BaseToolWrapper):
    """Wrapper for sqlmap SQL injection testing workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize sqlmap wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="sqlmap",
                image="saber/sqlmap:latest",
                phase=AssessmentPhase.EXPLOITATION,
                category=RequestedActionCategory.WEB,
                requested_by="SqlmapWrapper",
                default_timeout_seconds=1800,
                default_metadata={"tool_family": "web", "tool": "sqlmap"},
            ),
        )

    def test_url(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        risk: int = 1,
        level: int = 1,
        batch: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Test a URL with sqlmap."""

        return self.run(
            target=target,
            session=session,
            action="test_url",
            url=url,
            risk=risk,
            level=level,
            batch=batch,
            metadata=metadata,
        )

    def test_request(
        self,
        target: Target,
        session: MissionSession,
        request_file: str,
        risk: int = 1,
        level: int = 1,
        batch: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Test a captured request file with sqlmap."""

        return self.run(
            target=target,
            session=session,
            action="test_request",
            request_file=request_file,
            risk=risk,
            level=level,
            batch=batch,
            metadata=metadata,
        )

    def dump_schema(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        batch: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate database schema with sqlmap."""

        return self.run(
            target=target,
            session=session,
            action="dump_schema",
            url=url,
            batch=batch,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a sqlmap ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            **(kwargs.get("metadata") or {}),
        }

        if action in ("test_url", "injection_test"):
            url = self._url_from_target_or_kwargs(target, kwargs)
            command = ["sqlmap", "-u", url]
            self._append_common_options(command, kwargs)

            return ToolCommand(
                command=command,
                action=action,
                evidence_title=f"sqlmap URL test: {url}",
                evidence_relative_dir="web/sqlmap/test_url",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "url": url,
                    "risk": kwargs.get("risk", 1),
                    "level": kwargs.get("level", 1),
                    "batch": bool(kwargs.get("batch", True)),
                },
            )

        if action == "test_request":
            request_file = self._required_string(kwargs, "request_file")
            command = ["sqlmap", "-r", request_file]
            self._append_common_options(command, kwargs)

            return ToolCommand(
                command=command,
                action="test_request",
                evidence_title=f"sqlmap request test: {request_file}",
                evidence_relative_dir="web/sqlmap/test_request",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "request_file": request_file,
                    "risk": kwargs.get("risk", 1),
                    "level": kwargs.get("level", 1),
                    "batch": bool(kwargs.get("batch", True)),
                },
            )

        if action == "dump_schema":
            url = self._url_from_target_or_kwargs(target, kwargs)
            command = ["sqlmap", "-u", url, "--schema"]
            if bool(kwargs.get("batch", True)):
                command.append("--batch")

            return ToolCommand(
                command=command,
                action="dump_schema",
                evidence_title=f"sqlmap schema: {url}",
                evidence_relative_dir="web/sqlmap/dump_schema",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "url": url, "batch": bool(kwargs.get("batch", True))},
            )

        raise ValueError(f"Unsupported sqlmap action: {action}")

    @classmethod
    def _append_common_options(cls, command: list[str], kwargs: dict[str, Any]) -> None:
        """Append sqlmap risk/level/batch options."""

        risk = cls._range_int(kwargs.get("risk", 1), "risk", 1, 3)
        level = cls._range_int(kwargs.get("level", 1), "level", 1, 5)
        command.extend(["--risk", str(risk), "--level", str(level)])
        if bool(kwargs.get("batch", True)):
            command.append("--batch")

    @staticmethod
    def _range_int(value: Any, key: str, minimum: int, maximum: int) -> int:
        """Validate integer range."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be between {minimum} and {maximum}") from exc
        if parsed < minimum or parsed > maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}")
        return parsed

    @classmethod
    def _url_from_target_or_kwargs(cls, target: Target | str | None, kwargs: dict[str, Any]) -> str:
        """Resolve URL from explicit kwarg or Target."""

        explicit = kwargs.get("url")
        if explicit is not None:
            return cls._string_value(explicit, "url")
        if isinstance(target, Target):
            return cls._string_value(target.tool_value(), "url")
        return cls._required_string(kwargs, "url")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        if key not in kwargs:
            raise ValueError(f"{key} is required")
        return cls._string_value(kwargs[key], key)

    @staticmethod
    def _string_value(value: Any, key: str) -> str:
        """Convert and validate a string-like value."""

        text = str(value).strip()
        if not text:
            raise ValueError(f"{key} is required")
        return text
