"""Tests for reconnaissance tool wrappers."""

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
from saber.tools.recon import (
    AmassWrapper,
    DNSReconWrapper,
    MasscanWrapper,
    NmapWrapper,
    SubfinderWrapper,
    TheHarvesterWrapper,
    WhatWebWrapper,
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


def make_domain_target() -> Target:
    """Create reusable domain target."""

    return Target(type=TargetType.DOMAIN, value="example.com")


def make_host_target() -> Target:
    """Create reusable host target."""

    return Target(type=TargetType.HOST, value="192.0.2.10")


def make_url_target() -> Target:
    """Create reusable URL target."""

    return Target(type=TargetType.URL, value="https://example.com")


def make_session() -> MissionSession:
    """Create reusable mission session."""

    return MissionSession(
        session_id="session_recon_1",
        mission_name="Recon Wrapper Test Mission",
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


class TestReconExports:
    """Validate recon package exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export recon wrapper classes."""

        assert AmassWrapper is not None
        assert DNSReconWrapper is not None
        assert MasscanWrapper is not None
        assert NmapWrapper is not None
        assert SubfinderWrapper is not None
        assert TheHarvesterWrapper is not None
        assert WhatWebWrapper is not None


class TestAmassWrapper:
    """Validate Amass wrapper."""

    def test_default_config(self) -> None:
        """Amass should use recon defaults."""

        wrapper = AmassWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "amass"
        assert wrapper.config.image == "saber/amass:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_enum_passive_command(self) -> None:
        """Passive enum should build amass enum passive command."""

        wrapper = AmassWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_domain_target(),
            action="enum_passive",
            output_file="amass.txt",
        )

        assert command.command == ["amass", "enum", "-passive", "-d", "example.com", "-o", "amass.txt"]
        assert command.action == "enum_passive"
        assert command.evidence_relative_dir == "recon/amass/enum_passive"

    def test_enum_active_command(self) -> None:
        """Active enum should include resolver and output options."""

        wrapper = AmassWrapper(FakeSandbox())
        command = wrapper.build_command(
            action="enum_active",
            domain="example.com",
            resolvers_file="resolvers.txt",
            output_file="active.txt",
        )

        assert command.command == [
            "amass",
            "enum",
            "-active",
            "-d",
            "example.com",
            "-rf",
            "resolvers.txt",
            "-o",
            "active.txt",
        ]

    def test_intel_delegates_to_sandbox(self) -> None:
        """Intel method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = AmassWrapper(sandbox)

        wrapper.intel(target=make_domain_target(), session=make_session())

        assert sandbox.requests[0].command == ["amass", "intel", "-d", "example.com", "-whois"]
        assert sandbox.requests[0].tool_request.action == "intel"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.RECON

    def test_db_export_command(self) -> None:
        """DB export should build amass db command."""

        wrapper = AmassWrapper(FakeSandbox())
        command = wrapper.build_command(action="db_export", domain="example.com", output_file="graph.json")

        assert command.command == ["amass", "db", "-d", "example.com", "-json", "graph.json"]

    def test_missing_domain_raises(self) -> None:
        """Missing domain should raise."""

        wrapper = AmassWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="domain is required"):
            wrapper.build_command(action="enum_passive", domain="")


class TestDNSReconWrapper:
    """Validate DNSRecon wrapper."""

    def test_default_config(self) -> None:
        """DNSRecon should use recon defaults."""

        wrapper = DNSReconWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "dnsrecon"
        assert wrapper.config.image == "saber/dnsrecon:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_standard_command(self) -> None:
        """Standard DNSRecon should include domain and nameserver."""

        wrapper = DNSReconWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_domain_target(),
            action="standard",
            nameserver="1.1.1.1",
            json_output="dns.json",
        )

        assert command.command == ["dnsrecon", "-d", "example.com", "-t", "std", "-n", "1.1.1.1", "-j", "dns.json"]
        assert command.action == "standard"

    def test_zone_transfer_delegates_to_sandbox(self) -> None:
        """Zone transfer method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = DNSReconWrapper(sandbox)

        wrapper.zone_transfer(target=make_domain_target(), session=make_session(), nameserver="8.8.8.8")

        assert sandbox.requests[0].command == ["dnsrecon", "-d", "example.com", "-t", "axfr", "-n", "8.8.8.8"]
        assert sandbox.requests[0].tool_request.action == "zone_transfer"

    def test_brute_force_command(self) -> None:
        """Brute-force command should include wordlist."""

        wrapper = DNSReconWrapper(FakeSandbox())
        command = wrapper.build_command(action="brute_force", domain="example.com", wordlist="subs.txt")

        assert command.command == ["dnsrecon", "-d", "example.com", "-t", "brt", "-D", "subs.txt"]

    def test_reverse_lookup_command(self) -> None:
        """Reverse lookup should use -r."""

        wrapper = DNSReconWrapper(FakeSandbox())
        command = wrapper.build_command(action="reverse_lookup", cidr="192.0.2.0/24", json_output="rev.json")

        assert command.command == ["dnsrecon", "-r", "192.0.2.0/24", "-j", "rev.json"]

    def test_missing_wordlist_raises(self) -> None:
        """Missing wordlist should raise."""

        wrapper = DNSReconWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="wordlist is required"):
            wrapper.build_command(action="brute_force", domain="example.com", wordlist="")


class TestMasscanWrapper:
    """Validate Masscan wrapper."""

    def test_default_config(self) -> None:
        """Masscan should use recon defaults."""

        wrapper = MasscanWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "masscan"
        assert wrapper.config.image == "saber/masscan:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_scan_ports_command(self) -> None:
        """Masscan should build port scan command."""

        wrapper = MasscanWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_host_target(),
            action="scan_ports",
            ports="80,443",
            rate=5000,
            output_file="masscan.json",
        )

        assert command.command == [
            "masscan",
            "192.0.2.10",
            "-p",
            "80,443",
            "--rate",
            "5000",
            "-oJ",
            "masscan.json",
        ]
        assert command.action == "scan_ports"

    def test_top_ports_delegates_to_sandbox(self) -> None:
        """Top ports should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = MasscanWrapper(sandbox)

        wrapper.top_ports(target=make_host_target(), session=make_session())

        assert sandbox.requests[0].command == [
            "masscan",
            "192.0.2.10",
            "-p",
            "80,443,445,3389,22",
            "--rate",
            "1000",
        ]
        assert sandbox.requests[0].tool_request.action == "scan_ports"

    def test_exclude_file_scan_command(self) -> None:
        """Exclude file scan should include excludefile."""

        wrapper = MasscanWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_host_target(),
            action="exclude_file_scan",
            ports="1-1024",
            exclude_file="exclude.txt",
        )

        assert command.command == [
            "masscan",
            "192.0.2.10",
            "-p",
            "1-1024",
            "--rate",
            "1000",
            "--excludefile",
            "exclude.txt",
        ]

    def test_bad_rate_raises(self) -> None:
        """Bad rate should raise."""

        wrapper = MasscanWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="rate must be a positive integer"):
            wrapper.build_command(target=make_host_target(), action="scan_ports", ports="80", rate=0)


class TestNmapWrapper:
    """Validate Nmap wrapper."""

    def test_default_config(self) -> None:
        """Nmap should use recon defaults."""

        wrapper = NmapWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "nmap"
        assert wrapper.config.image == "saber/nmap:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_service_scan_command(self) -> None:
        """Service scan should include -sV and -sC."""

        wrapper = NmapWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_host_target(),
            action="service_scan",
            ports="80,443",
            output_prefix="nmap/service",
        )

        assert command.command == [
            "nmap", "-sT", "-sV", "-sC", "-Pn", "-p", "80,443", "-oA", "nmap/service", "192.0.2.10",
        ]
        assert command.action == "service_scan"

    def test_vuln_scan_delegates_to_sandbox(self) -> None:
        """Vuln scan should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = NmapWrapper(sandbox)

        wrapper.vuln_scan(target=make_host_target(), session=make_session(), ports="445")

        assert sandbox.requests[0].command == ["nmap", "-sV", "--script", "vuln", "-p", "445", "192.0.2.10"]
        assert sandbox.requests[0].tool_request.action == "vuln_scan"

    def test_udp_scan_command(self) -> None:
        """UDP scan should include -sU."""

        wrapper = NmapWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_host_target(), action="udp_scan", ports="53,161")

        assert command.command == ["nmap", "-sU", "-Pn", "-p", "53,161", "192.0.2.10"]

    def test_script_scan_command(self) -> None:
        """Script scan should include script name."""

        wrapper = NmapWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_host_target(),
            action="script_scan",
            script="http-title",
            ports="80",
        )

        assert command.command == ["nmap", "-sV", "--script", "http-title", "-p", "80", "192.0.2.10"]
        assert command.metadata["script"] == "http-title"

    def test_missing_script_raises(self) -> None:
        """Missing script should raise."""

        wrapper = NmapWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="script is required"):
            wrapper.build_command(target=make_host_target(), action="script_scan", script="")


class TestSubfinderWrapper:
    """Validate Subfinder wrapper."""

    def test_default_config(self) -> None:
        """Subfinder should use recon defaults."""

        wrapper = SubfinderWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "subfinder"
        assert wrapper.config.image == "saber/subfinder:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_enumerate_command(self) -> None:
        """Enumerate should build subfinder command."""

        wrapper = SubfinderWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_domain_target(),
            action="enumerate",
            output_file="subs.txt",
            silent=True,
        )

        assert command.command == ["subfinder", "-d", "example.com", "-silent", "-o", "subs.txt"]
        assert command.action == "enumerate"

    def test_enumerate_all_sources_delegates_to_sandbox(self) -> None:
        """All sources should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SubfinderWrapper(sandbox)

        wrapper.enumerate_all_sources(target=make_domain_target(), session=make_session(), output_file="all.txt")

        assert sandbox.requests[0].command == ["subfinder", "-d", "example.com", "-all", "-silent", "-o", "all.txt"]
        assert sandbox.requests[0].tool_request.action == "enumerate_all_sources"

    def test_enumerate_from_list_command(self) -> None:
        """List enumeration should include -dL."""

        wrapper = SubfinderWrapper(FakeSandbox())
        command = wrapper.build_command(action="enumerate_from_list", domain_list="domains.txt", output_file="subs.txt")

        assert command.command == ["subfinder", "-dL", "domains.txt", "-o", "subs.txt"]

    def test_missing_domain_list_raises(self) -> None:
        """Missing domain list should raise."""

        wrapper = SubfinderWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="domain_list is required"):
            wrapper.build_command(action="enumerate_from_list", domain_list="")


class TestTheHarvesterWrapper:
    """Validate theHarvester wrapper."""

    def test_default_config(self) -> None:
        """theHarvester should use recon defaults."""

        wrapper = TheHarvesterWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "theharvester"
        assert wrapper.config.image == "saber/theharvester:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_search_command(self) -> None:
        """Search should build theHarvester command."""

        wrapper = TheHarvesterWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_domain_target(),
            action="search",
            sources="bing,crtsh",
            limit=100,
            output_file="harvester",
        )

        assert command.command == [
            "theHarvester",
            "-d",
            "example.com",
            "-b",
            "bing,crtsh",
            "-l",
            "100",
            "-f",
            "harvester",
        ]
        assert command.action == "search"

    def test_email_search_delegates_to_sandbox(self) -> None:
        """Email search should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = TheHarvesterWrapper(sandbox)

        wrapper.email_search(target=make_domain_target(), session=make_session(), sources="bing")

        assert sandbox.requests[0].command == ["theHarvester", "-d", "example.com", "-b", "bing"]
        assert sandbox.requests[0].tool_request.action == "email_search"

    def test_host_search_command(self) -> None:
        """Host search should use host evidence dir."""

        wrapper = TheHarvesterWrapper(FakeSandbox())
        command = wrapper.build_command(action="host_search", domain="example.com", sources="crtsh")

        assert command.command == ["theHarvester", "-d", "example.com", "-b", "crtsh"]
        assert command.evidence_relative_dir == "recon/theharvester/host_search"

    def test_bad_limit_raises(self) -> None:
        """Bad limit should raise."""

        wrapper = TheHarvesterWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="limit must be a positive integer"):
            wrapper.build_command(action="search", domain="example.com", sources="bing", limit=0)


class TestWhatWebWrapper:
    """Validate WhatWeb wrapper."""

    def test_default_config(self) -> None:
        """WhatWeb should use recon defaults."""

        wrapper = WhatWebWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "whatweb"
        assert wrapper.config.image == "saber/whatweb:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.RECON

    def test_fingerprint_command(self) -> None:
        """Fingerprint should build WhatWeb command."""

        wrapper = WhatWebWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_url_target(),
            action="fingerprint",
            aggression=2,
            json_output="whatweb.json",
        )

        assert command.command == ["whatweb", "-a", "2", "https://example.com/", "--log-json", "whatweb.json"]
        assert command.action == "fingerprint"

    def test_aggressive_delegates_to_sandbox(self) -> None:
        """Aggressive method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = WhatWebWrapper(sandbox)

        wrapper.aggressive(target=make_url_target(), session=make_session())

        assert sandbox.requests[0].command == ["whatweb", "-a", "3", "https://example.com/"]
        assert sandbox.requests[0].tool_request.action == "aggressive"

    def test_list_scan_command(self) -> None:
        """List scan should use -i."""

        wrapper = WhatWebWrapper(FakeSandbox())
        command = wrapper.build_command(action="list_scan", input_file="urls.txt", aggression=1)

        assert command.command == ["whatweb", "-a", "1", "-i", "urls.txt"]

    def test_missing_input_file_raises(self) -> None:
        """Missing input file should raise."""

        wrapper = WhatWebWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="input_file is required"):
            wrapper.build_command(action="list_scan", input_file="")


class TestCustomConfigs:
    """Validate custom ToolWrapperConfig support."""

    def test_custom_nmap_config(self) -> None:
        """Nmap should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_nmap",
            image="custom/nmap:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.RECON,
            requested_by="CustomNmap",
        )

        wrapper = NmapWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_nmap"
        assert wrapper.config.image == "custom/nmap:dev"

    def test_custom_whatweb_config(self) -> None:
        """WhatWeb should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_whatweb",
            image="custom/whatweb:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.RECON,
            requested_by="CustomWhatWeb",
        )

        wrapper = WhatWebWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_whatweb"
        assert wrapper.config.image == "custom/whatweb:dev"


class TestToolCommandValidation:
    """Validate ToolCommand remains available for recon wrappers."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
