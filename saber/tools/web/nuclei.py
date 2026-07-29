"""Nuclei wrapper for SABER."""

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
    tool_name="nuclei",
    category="web",
    phase="recon",
    description="Template-based vulnerability scanning.",
    parser="nuclei",
    actions=(
        ActionContract(
            action="template_scan",
            description="Run Nuclei templates filtered by severity against a target.",
            args=(
                ArgSpec(
                    "severity",
                    "str",
                    required=False,
                    default="low,medium,high,critical",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("vuln",),
            example_args={"severity": "high,critical"},
        ),
    ),
)


class NucleiWrapper(BaseToolWrapper):
    """Wrapper for Nuclei template-based scanning."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Nuclei wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="nuclei",
                image="saber/nuclei:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.WEB,
                requested_by="NucleiWrapper",
                default_timeout_seconds=1800,
                default_metadata={"tool_family": "web", "tool": "nuclei"},
            ),
        )

    def scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        templates: str | None = None,
        severity: str | None = None,
        output_file: str | None = None,
        jsonl: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Nuclei scan."""

        return self.run(
            target=target,
            session=session,
            action="scan",
            url=url,
            templates=templates,
            severity=severity,
            output_file=output_file,
            jsonl=jsonl,
            metadata=metadata,
        )

    def template_scan(
        self,
        target: Target,
        session: MissionSession,
        templates: str,
        url: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Nuclei with a specific template path."""

        return self.scan(target=target, session=session, url=url, templates=templates, metadata=metadata)

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Nuclei ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")
        if action not in ("scan", "template_scan"):
            raise ValueError(f"Unsupported Nuclei action: {action}")

        url = self._url_from_target_or_kwargs(target, kwargs)
        command = ["nuclei", "-u", url]

        templates = kwargs.get("templates")
        if templates:
            command.extend(["-t", str(templates)])

        severity = kwargs.get("severity")
        if severity:
            severity = self._validate_severity(severity)
            command.extend(["-severity", severity])

        output_file = kwargs.get("output_file")
        if output_file:
            command.extend(["-o", str(output_file)])

        jsonl = bool(kwargs.get("jsonl", False))
        if jsonl:
            command.append("-jsonl")

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=f"Nuclei scan: {url}",
            evidence_relative_dir="web/nuclei/scan",
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "url": url,
                "templates": templates,
                "severity": severity,
                "output_file": output_file,
                "jsonl": jsonl,
                "target": target.tool_value() if isinstance(target, Target) else None,
                **(kwargs.get("metadata") or {}),
            },
        )

    @staticmethod
    def _validate_severity(value: Any) -> str:
        """Validate Nuclei severity filter."""

        severity = str(value).strip().lower()
        allowed = {"info", "low", "medium", "high", "critical", "unknown"}
        parts = [part.strip() for part in severity.split(",") if part.strip()]
        if not parts or any(part not in allowed for part in parts):
            raise ValueError("severity must contain valid nuclei severities")
        return ",".join(parts)

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
