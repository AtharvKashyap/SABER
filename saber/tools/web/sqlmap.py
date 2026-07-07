"""sqlmap wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


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

        if action == "test_url":
            url = self._url_from_target_or_kwargs(target, kwargs)
            command = ["sqlmap", "-u", url]
            self._append_common_options(command, kwargs)

            return ToolCommand(
                command=command,
                action="test_url",
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
