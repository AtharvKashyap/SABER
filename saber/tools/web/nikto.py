"""Nikto wrapper for SABER."""

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
    tool_name="nikto",
    category="web",
    phase="recon",
    description="Web server vulnerability scanning.",
    parser="nikto",
    actions=(
        ActionContract(
            action="web_scan",
            description="Run a Nikto scan against a web target.",
            args=(
                ArgSpec("target", "str", required=True, description="URL/host in scope."),
                ArgSpec("port", "str", required=False, example="8080"),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("vuln",),
            example_args={"target": "https://127.0.0.1"},
        ),
    ),
)


class NiktoWrapper(BaseToolWrapper):
    """Wrapper for Nikto web server scanning."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Nikto wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="nikto",
                image="saber/nikto:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.WEB,
                requested_by="NiktoWrapper",
                default_timeout_seconds=1200,
                default_metadata={"tool_family": "web", "tool": "nikto"},
            ),
        )

    def scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        output_file: str | None = None,
        output_format: str | None = None,
        tuning: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Nikto scan."""

        return self.run(
            target=target,
            session=session,
            action="scan",
            url=url,
            output_file=output_file,
            output_format=output_format,
            tuning=tuning,
            metadata=metadata,
        )

    def quick_scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run basic Nikto scan."""

        return self.scan(target=target, session=session, url=url, metadata=metadata)

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Nikto ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")
        if action not in ("scan", "web_scan"):
            raise ValueError(f"Unsupported Nikto action: {action}")

        url = self._url_from_target_or_kwargs(target, kwargs)
        command = ["nikto", "-h", url]

        port = kwargs.get("port")
        if port:
            command.extend(["-p", str(port)])

        output_file = kwargs.get("output_file")
        if output_file:
            command.extend(["-o", str(output_file)])

        output_format = kwargs.get("output_format")
        if output_format:
            output_format = self._validate_output_format(output_format)
            command.extend(["-Format", output_format])

        tuning = kwargs.get("tuning")
        if tuning:
            command.extend(["-Tuning", str(tuning)])

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=f"Nikto scan: {url}",
            evidence_relative_dir="web/nikto/scan",
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "url": url,
                "port": port,
                "output_file": output_file,
                "output_format": output_format,
                "tuning": tuning,
                "target": target.tool_value() if isinstance(target, Target) else None,
                **(kwargs.get("metadata") or {}),
            },
        )

    @staticmethod
    def _validate_output_format(value: Any) -> str:
        """Validate Nikto output format."""

        output_format = str(value).strip().lower()
        if output_format not in {"txt", "csv", "json", "xml", "html"}:
            raise ValueError("output_format must be one of: txt, csv, json, xml, html")
        return output_format

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
