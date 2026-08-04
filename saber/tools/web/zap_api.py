"""OWASP ZAP API wrapper for SABER."""

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
    tool_name="zap_api",
    category="web",
    phase="recon",
    description="OWASP ZAP crawling and active vulnerability scanning via zap-cli/zap-baseline.",
    parser="zap",
    aliases=("zap",),
    actions=(
        ActionContract(
            action="baseline_scan",
            description="zap-baseline.py passive spider + baseline alert scan.",
            args=(
                ArgSpec(
                    "report_file",
                    "str",
                    required=False,
                    default=None,
                    description="Optional path to write the ZAP report.",
                    example="/evidence/zap_baseline.html",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("vuln", "note"),
            example_args={},
        ),
        ActionContract(
            action="spider",
            description="zap-cli spider crawl to enumerate reachable URLs.",
            args=(
                ArgSpec(
                    "zap_url",
                    "str",
                    required=True,
                    description="Base URL of the running ZAP API daemon.",
                    example="http://127.0.0.1:8080",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={"zap_url": "http://127.0.0.1:8080"},
        ),
        ActionContract(
            action="active_scan",
            description="zap-cli active-scan: intrusive attack payload scan against the target.",
            args=(
                ArgSpec(
                    "zap_url",
                    "str",
                    required=True,
                    description="Base URL of the running ZAP API daemon.",
                    example="http://127.0.0.1:8080",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("vuln", "note"),
            example_args={"zap_url": "http://127.0.0.1:8080"},
        ),
        ActionContract(
            action="export_report",
            description="zap-cli report: export the ZAP scan report from the running daemon.",
            args=(
                ArgSpec(
                    "report_file",
                    "str",
                    required=True,
                    description="Output path for the exported report.",
                    example="/evidence/zap_report.html",
                ),
                ArgSpec(
                    "zap_url",
                    "str",
                    required=True,
                    description="Base URL of the running ZAP API daemon.",
                    example="http://127.0.0.1:8080",
                ),
                ArgSpec(
                    "report_format",
                    "str",
                    required=False,
                    default="html",
                    choices=("html", "xml", "json", "md"),
                    example="html",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={
                "report_file": "/evidence/zap_report.html",
                "zap_url": "http://127.0.0.1:8080",
            },
        ),
    ),
)


class ZAPApiWrapper(BaseToolWrapper):
    """Wrapper for OWASP ZAP API and packaged scan commands."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize ZAP API wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="zap_api",
                image="saber/zap-api:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.WEB,
                requested_by="ZAPApiWrapper",
                default_timeout_seconds=1800,
                default_metadata={"tool_family": "web", "tool": "zap_api"},
            ),
        )

    def baseline_scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        report_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run ZAP baseline scan."""

        return self.run(
            target=target,
            session=session,
            action="baseline_scan",
            url=url,
            report_file=report_file,
            metadata=metadata,
        )

    def spider(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        zap_url: str = "http://127.0.0.1:8080",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run ZAP spider through API helper."""

        return self.run(
            target=target,
            session=session,
            action="spider",
            url=url,
            zap_url=zap_url,
            metadata=metadata,
        )

    def active_scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        zap_url: str = "http://127.0.0.1:8080",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run ZAP active scan through API helper."""

        return self.run(
            target=target,
            session=session,
            action="active_scan",
            url=url,
            zap_url=zap_url,
            metadata=metadata,
        )

    def export_report(
        self,
        target: Target,
        session: MissionSession,
        report_file: str,
        zap_url: str = "http://127.0.0.1:8080",
        report_format: str = "html",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Export ZAP report."""

        return self.run(
            target=target,
            session=session,
            action="export_report",
            report_file=report_file,
            zap_url=zap_url,
            report_format=report_format,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a ZAP API ToolCommand."""

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

        if action == "baseline_scan":
            url = self._url_from_target_or_kwargs(target, kwargs)
            command = ["zap-baseline.py", "-t", url]
            report_file = kwargs.get("report_file")
            if report_file:
                command.extend(["-r", str(report_file)])

            return ToolCommand(
                command=command,
                action="baseline_scan",
                evidence_title=f"ZAP baseline scan: {url}",
                evidence_relative_dir="web/zap_api/baseline_scan",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "url": url, "report_file": report_file},
            )

        if action == "spider":
            url = self._url_from_target_or_kwargs(target, kwargs)
            zap_url = self._required_string(kwargs, "zap_url")

            return ToolCommand(
                command=["zap-cli", "--zap-url", zap_url, "spider", url],
                action="spider",
                evidence_title=f"ZAP spider: {url}",
                evidence_relative_dir="web/zap_api/spider",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "url": url, "zap_url": zap_url},
            )

        if action == "active_scan":
            url = self._url_from_target_or_kwargs(target, kwargs)
            zap_url = self._required_string(kwargs, "zap_url")

            return ToolCommand(
                command=["zap-cli", "--zap-url", zap_url, "active-scan", url],
                action="active_scan",
                evidence_title=f"ZAP active scan: {url}",
                evidence_relative_dir="web/zap_api/active_scan",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "url": url, "zap_url": zap_url},
            )

        if action == "export_report":
            report_file = self._required_string(kwargs, "report_file")
            zap_url = self._required_string(kwargs, "zap_url")
            report_format = self._validate_report_format(kwargs.get("report_format", "html"))

            return ToolCommand(
                command=["zap-cli", "--zap-url", zap_url, "report", "-f", report_format, "-o", report_file],
                action="export_report",
                evidence_title=f"ZAP report export: {report_file}",
                evidence_relative_dir="web/zap_api/export_report",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "report_file": report_file, "zap_url": zap_url, "report_format": report_format},
            )

        raise ValueError(f"Unsupported ZAP API action: {action}")

    @staticmethod
    def _validate_report_format(value: Any) -> str:
        """Validate ZAP report format."""

        report_format = str(value).strip().lower()
        if report_format not in {"html", "xml", "json", "md"}:
            raise ValueError("report_format must be one of: html, xml, json, md")
        return report_format

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
