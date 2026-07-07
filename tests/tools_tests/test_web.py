"""Tests for web application testing tool wrappers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.base_wrapper import ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.web import (
    FeroxbusterWrapper,
    NiktoWrapper,
    NucleiWrapper,
    SqlmapWrapper,
    ZAPApiWrapper,
)


@dataclass
class FakeSandbox:
    """Fake sandbox that records requests and returns a configured result."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request and return configured result."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_url_target() -> Target:
    """Create reusable URL target."""

    return Target(type=TargetType.URL, value="https://example.com")


def make_session() -> MissionSession:
    """Create reusable mission session."""

    return MissionSession(
        session_id="session_web_1",
        mission_name="Web Wrapper Test Mission",
        status=SessionStatus.CREATED,
    )


def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create reusable sandbox result."""

    return SandboxExecutionResult(
        outcome=SandboxOutcome.EXECUTED,
        allowed=True,
        session=session or make_session(),
        evidence=None,
        return_code=0,
        stdout="ok",
        stderr="",
        reason="Command executed and evidence was saved.",
        metadata={"backend": "fake", "finished_at": datetime.now(UTC).isoformat()},
    )


class TestWebExports:
    """Validate web package exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export web wrappers."""

        assert FeroxbusterWrapper is not None
        assert NiktoWrapper is not None
        assert NucleiWrapper is not None
        assert SqlmapWrapper is not None
        assert ZAPApiWrapper is not None


class TestFeroxbusterWrapper:
    """Validate Feroxbuster wrapper."""

    def test_default_config(self) -> None:
        """Feroxbuster should use web defaults."""

        wrapper = FeroxbusterWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "feroxbuster"
        assert wrapper.config.image == "saber/feroxbuster:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.WEB
        assert wrapper.config.requested_by == "FeroxbusterWrapper"

    def test_directory_bruteforce_command(self) -> None:
        """Directory bruteforce should include URL, wordlist, threads, extensions, and output."""

        wrapper = FeroxbusterWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="directory_bruteforce",
            wordlist="wordlists/common.txt",
            extensions=["php", "txt"],
            threads=25,
            output_file="ferox.txt",
        )

        assert command.command == [
            "feroxbuster",
            "-u",
            "https://example.com/",
            "-w",
            "wordlists/common.txt",
            "-t",
            "25",
            "-x",
            "php,txt",
            "-o",
            "ferox.txt",
        ]
        assert command.action == "directory_bruteforce"
        assert command.evidence_relative_dir == "web/feroxbuster/directory_bruteforce"
        assert command.metadata["extensions"] == ["php", "txt"]

    def test_quick_scan_delegates_to_sandbox(self) -> None:
        """Quick scan should execute through Sandbox with reduced threads."""

        sandbox = FakeSandbox()
        wrapper = FeroxbusterWrapper(sandbox)

        wrapper.quick_scan(target=make_url_target(), session=make_session())

        assert sandbox.requests[0].command == [
            "feroxbuster",
            "-u",
            "https://example.com/",
            "-w",
            "wordlists/common.txt",
            "-t",
            "20",
        ]
        assert sandbox.requests[0].tool_request.action == "directory_bruteforce"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.WEB

    def test_bad_threads_raises(self) -> None:
        """Bad threads value should raise."""

        wrapper = FeroxbusterWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="threads must be a positive integer"):
            wrapper.build_command(
                target=make_url_target(),
                action="directory_bruteforce",
                wordlist="wordlists/common.txt",
                threads=0,
            )

    def test_missing_wordlist_raises(self) -> None:
        """Missing wordlist should raise."""

        wrapper = FeroxbusterWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="wordlist is required"):
            wrapper.build_command(target=make_url_target(), action="directory_bruteforce", wordlist="")


class TestNiktoWrapper:
    """Validate Nikto wrapper."""

    def test_default_config(self) -> None:
        """Nikto should use web defaults."""

        wrapper = NiktoWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "nikto"
        assert wrapper.config.image == "saber/nikto:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.WEB
        assert wrapper.config.requested_by == "NiktoWrapper"

    def test_scan_command(self) -> None:
        """Nikto scan should include output file, format, and tuning."""

        wrapper = NiktoWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="scan",
            output_file="nikto.json",
            output_format="json",
            tuning="123",
        )

        assert command.command == [
            "nikto",
            "-h",
            "https://example.com/",
            "-o",
            "nikto.json",
            "-Format",
            "json",
            "-Tuning",
            "123",
        ]
        assert command.action == "scan"
        assert command.evidence_relative_dir == "web/nikto/scan"

    def test_quick_scan_delegates_to_sandbox(self) -> None:
        """Quick scan should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = NiktoWrapper(sandbox)

        wrapper.quick_scan(target=make_url_target(), session=make_session())

        assert sandbox.requests[0].command == ["nikto", "-h", "https://example.com/"]
        assert sandbox.requests[0].tool_request.action == "scan"

    def test_bad_output_format_raises(self) -> None:
        """Bad output format should raise."""

        wrapper = NiktoWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="output_format must be one of"):
            wrapper.build_command(target=make_url_target(), action="scan", output_format="yaml")

    def test_unsupported_action_raises(self) -> None:
        """Unsupported action should raise."""

        wrapper = NiktoWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported Nikto action"):
            wrapper.build_command(target=make_url_target(), action="bad")


class TestNucleiWrapper:
    """Validate Nuclei wrapper."""

    def test_default_config(self) -> None:
        """Nuclei should use web defaults."""

        wrapper = NucleiWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "nuclei"
        assert wrapper.config.image == "saber/nuclei:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.WEB
        assert wrapper.config.requested_by == "NucleiWrapper"

    def test_scan_command(self) -> None:
        """Nuclei scan should include templates, severity, output, and jsonl."""

        wrapper = NucleiWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="scan",
            templates="templates/cves",
            severity="high,critical",
            output_file="nuclei.txt",
            jsonl=True,
        )

        assert command.command == [
            "nuclei",
            "-u",
            "https://example.com/",
            "-t",
            "templates/cves",
            "-severity",
            "high,critical",
            "-o",
            "nuclei.txt",
            "-jsonl",
        ]
        assert command.action == "scan"
        assert command.evidence_relative_dir == "web/nuclei/scan"
        assert command.metadata["severity"] == "high,critical"

    def test_template_scan_delegates_to_sandbox(self) -> None:
        """Template scan should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = NucleiWrapper(sandbox)

        wrapper.template_scan(
            target=make_url_target(),
            session=make_session(),
            templates="templates/http/exposures",
        )

        assert sandbox.requests[0].command == [
            "nuclei",
            "-u",
            "https://example.com/",
            "-t",
            "templates/http/exposures",
        ]
        assert sandbox.requests[0].tool_request.action == "scan"

    def test_bad_severity_raises(self) -> None:
        """Bad severity should raise."""

        wrapper = NucleiWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="severity must contain valid nuclei severities"):
            wrapper.build_command(target=make_url_target(), action="scan", severity="urgent")

    def test_unsupported_action_raises(self) -> None:
        """Unsupported action should raise."""

        wrapper = NucleiWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported Nuclei action"):
            wrapper.build_command(target=make_url_target(), action="bad")


class TestSqlmapWrapper:
    """Validate sqlmap wrapper."""

    def test_default_config(self) -> None:
        """sqlmap should use web defaults."""

        wrapper = SqlmapWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "sqlmap"
        assert wrapper.config.image == "saber/sqlmap:latest"
        assert wrapper.config.phase == AssessmentPhase.EXPLOITATION
        assert wrapper.config.category == RequestedActionCategory.WEB
        assert wrapper.config.requested_by == "SqlmapWrapper"

    def test_test_url_command(self) -> None:
        """test_url should include URL, risk, level, and batch."""

        wrapper = SqlmapWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="test_url",
            risk=2,
            level=3,
            batch=True,
        )

        assert command.command == [
            "sqlmap",
            "-u",
            "https://example.com/",
            "--risk",
            "2",
            "--level",
            "3",
            "--batch",
        ]
        assert command.action == "test_url"
        assert command.evidence_relative_dir == "web/sqlmap/test_url"

    def test_test_request_command(self) -> None:
        """test_request should include request file."""

        wrapper = SqlmapWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="test_request",
            request_file="requests/login.txt",
            risk=1,
            level=2,
            batch=False,
        )

        assert command.command == ["sqlmap", "-r", "requests/login.txt", "--risk", "1", "--level", "2"]
        assert command.action == "test_request"

    def test_dump_schema_requires_authorization(self) -> None:
        """dump_schema should be explicit authorization."""

        wrapper = SqlmapWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_url_target(), action="dump_schema")

        assert command.command == ["sqlmap", "-u", "https://example.com/", "--schema", "--batch"]
        assert command.requires_explicit_authorization is True
        assert command.evidence_relative_dir == "web/sqlmap/dump_schema"

    def test_test_url_delegates_to_sandbox(self) -> None:
        """test_url method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SqlmapWrapper(sandbox)

        wrapper.test_url(target=make_url_target(), session=make_session(), risk=1, level=1)

        assert sandbox.requests[0].command == [
            "sqlmap",
            "-u",
            "https://example.com/",
            "--risk",
            "1",
            "--level",
            "1",
            "--batch",
        ]
        assert sandbox.requests[0].tool_request.action == "test_url"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.WEB

    def test_bad_risk_raises(self) -> None:
        """Bad risk should raise."""

        wrapper = SqlmapWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="risk must be between 1 and 3"):
            wrapper.build_command(target=make_url_target(), action="test_url", risk=4)

    def test_missing_request_file_raises(self) -> None:
        """Missing request file should raise."""

        wrapper = SqlmapWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="request_file is required"):
            wrapper.build_command(target=make_url_target(), action="test_request", request_file="")


class TestZAPApiWrapper:
    """Validate ZAP API wrapper."""

    def test_default_config(self) -> None:
        """ZAP API should use web defaults."""

        wrapper = ZAPApiWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "zap_api"
        assert wrapper.config.image == "saber/zap-api:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.WEB
        assert wrapper.config.requested_by == "ZAPApiWrapper"

    def test_baseline_scan_command(self) -> None:
        """Baseline scan should include target and report."""

        wrapper = ZAPApiWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="baseline_scan",
            report_file="zap.html",
        )

        assert command.command == ["zap-baseline.py", "-t", "https://example.com/", "-r", "zap.html"]
        assert command.action == "baseline_scan"
        assert command.evidence_relative_dir == "web/zap_api/baseline_scan"

    def test_spider_command(self) -> None:
        """Spider should use zap-cli."""

        wrapper = ZAPApiWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="spider",
            zap_url="http://127.0.0.1:8080",
        )

        assert command.command == [
            "zap-cli",
            "--zap-url",
            "http://127.0.0.1:8080",
            "spider",
            "https://example.com/",
        ]
        assert command.action == "spider"

    def test_active_scan_requires_authorization(self) -> None:
        """Active scan should require explicit authorization."""

        wrapper = ZAPApiWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="active_scan",
            zap_url="http://127.0.0.1:8080",
        )

        assert command.command == [
            "zap-cli",
            "--zap-url",
            "http://127.0.0.1:8080",
            "active-scan",
            "https://example.com/",
        ]
        assert command.requires_explicit_authorization is True

    def test_export_report_delegates_to_sandbox(self) -> None:
        """Export report should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = ZAPApiWrapper(sandbox)

        wrapper.export_report(
            target=make_url_target(),
            session=make_session(),
            report_file="zap.json",
            report_format="json",
        )

        assert sandbox.requests[0].command == [
            "zap-cli",
            "--zap-url",
            "http://127.0.0.1:8080",
            "report",
            "-f",
            "json",
            "-o",
            "zap.json",
        ]
        assert sandbox.requests[0].tool_request.action == "export_report"

    def test_bad_report_format_raises(self) -> None:
        """Bad report format should raise."""

        wrapper = ZAPApiWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="report_format must be one of"):
            wrapper.build_command(
                target=make_url_target(),
                action="export_report",
                report_file="zap.pdf",
                zap_url="http://127.0.0.1:8080",
                report_format="pdf",
            )

    def test_unsupported_action_raises(self) -> None:
        """Unsupported action should raise."""

        wrapper = ZAPApiWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported ZAP API action"):
            wrapper.build_command(target=make_url_target(), action="bad")


class TestCustomConfigs:
    """Validate custom ToolWrapperConfig support."""

    def test_custom_feroxbuster_config(self) -> None:
        """Feroxbuster should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_feroxbuster",
            image="custom/feroxbuster:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.WEB,
            requested_by="CustomFeroxbuster",
        )

        wrapper = FeroxbusterWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_feroxbuster"
        assert wrapper.config.image == "custom/feroxbuster:dev"

    def test_custom_sqlmap_config(self) -> None:
        """sqlmap should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_sqlmap",
            image="custom/sqlmap:dev",
            phase=AssessmentPhase.EXPLOITATION,
            category=RequestedActionCategory.WEB,
            requested_by="CustomSqlmap",
        )

        wrapper = SqlmapWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_sqlmap"
        assert wrapper.config.image == "custom/sqlmap:dev"

    def test_custom_zap_config(self) -> None:
        """ZAP API should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_zap",
            image="custom/zap:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.WEB,
            requested_by="CustomZAP",
        )

        wrapper = ZAPApiWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_zap"
        assert wrapper.config.image == "custom/zap:dev"


class TestToolCommandValidation:
    """Validate ToolCommand remains available for web wrappers."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
