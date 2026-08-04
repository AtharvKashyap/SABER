"""DNSRecon wrapper for SABER."""

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
    tool_name="dnsrecon",
    category="recon",
    phase="recon",
    description="Standard DNS enumeration.",
    parser="dnsrecon",
    actions=(
        ActionContract(
            action="standard",
            description="Standard DNSRecon enumeration (-t std).",
            args=(ArgSpec("domain", "str", required=True, description="Domain in scope."),),
            risk="low",
            requires_approval=False,
            emits_kinds=("host", "note"),
            example_args={"domain": "example.com"},
        ),
        ActionContract(
            action="zone_transfer",
            description="Attempt an AXFR zone transfer against the domain's nameservers.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec("nameserver", "str", required=False, description="Specific NS to query."),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "note"),
            example_args={"domain": "example.com"},
        ),
        ActionContract(
            action="brute_force",
            description="Brute-force subdomain names from a wordlist. Noisy: many DNS queries.",
            args=(
                ArgSpec("domain", "str", required=True, description="Domain in scope."),
                ArgSpec(
                    "wordlist",
                    "str",
                    required=True,
                    description="Path to a subdomain wordlist inside the sandbox.",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("host", "note"),
            example_args={"domain": "example.com", "wordlist": "/usr/share/wordlists/dns.txt"},
        ),
        ActionContract(
            action="reverse_lookup",
            description="Reverse-DNS sweep across an IP range to map names onto addresses.",
            args=(
                ArgSpec(
                    "cidr",
                    "str",
                    required=True,
                    description="IP range in scope, e.g. 192.168.56.0/24.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("host", "note"),
            example_args={"cidr": "192.168.56.0/24"},
        ),
    ),
)


class DNSReconWrapper(BaseToolWrapper):
    """Wrapper for DNSRecon DNS enumeration workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize DNSRecon wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="dnsrecon",
                image="saber/dnsrecon:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="DNSReconWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "recon", "tool": "dnsrecon"},
            ),
        )

    def standard(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        nameserver: str | None = None,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run standard DNSRecon enumeration."""

        return self.run(
            target=target,
            session=session,
            action="standard",
            domain=domain,
            nameserver=nameserver,
            json_output=json_output,
            metadata=metadata,
        )

    def zone_transfer(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        nameserver: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Attempt DNS zone transfer checks."""

        return self.run(
            target=target,
            session=session,
            action="zone_transfer",
            domain=domain,
            nameserver=nameserver,
            metadata=metadata,
        )

    def brute_force(
        self,
        target: Target,
        session: MissionSession,
        domain: str | None = None,
        wordlist: str | None = None,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run DNSRecon brute-force enumeration."""

        return self.run(
            target=target,
            session=session,
            action="brute_force",
            domain=domain,
            wordlist=wordlist,
            json_output=json_output,
            metadata=metadata,
        )

    def reverse_lookup(
        self,
        target: Target,
        session: MissionSession,
        cidr: str | None = None,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run reverse DNS lookup over a CIDR/range."""

        return self.run(
            target=target,
            session=session,
            action="reverse_lookup",
            cidr=cidr,
            json_output=json_output,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a DNSRecon ToolCommand."""

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

        if action == "standard":
            domain = self._domain_from_target_or_kwargs(target, kwargs)
            command = ["dnsrecon", "-d", domain, "-t", "std"]
            nameserver = kwargs.get("nameserver")
            json_output = kwargs.get("json_output")
            if nameserver:
                command.extend(["-n", str(nameserver)])
            if json_output:
                command.extend(["-j", str(json_output)])

            return ToolCommand(
                command=command,
                action="standard",
                evidence_title=f"DNSRecon standard: {domain}",
                evidence_relative_dir="recon/dnsrecon/standard",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "domain": domain, "nameserver": nameserver, "json_output": json_output},
            )

        if action == "zone_transfer":
            domain = self._domain_from_target_or_kwargs(target, kwargs)
            command = ["dnsrecon", "-d", domain, "-t", "axfr"]
            nameserver = kwargs.get("nameserver")
            if nameserver:
                command.extend(["-n", str(nameserver)])

            return ToolCommand(
                command=command,
                action="zone_transfer",
                evidence_title=f"DNSRecon AXFR: {domain}",
                evidence_relative_dir="recon/dnsrecon/zone_transfer",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "domain": domain, "nameserver": nameserver},
            )

        if action == "brute_force":
            domain = self._domain_from_target_or_kwargs(target, kwargs)
            wordlist = self._required_string(kwargs, "wordlist")
            command = ["dnsrecon", "-d", domain, "-t", "brt", "-D", wordlist]
            json_output = kwargs.get("json_output")
            if json_output:
                command.extend(["-j", str(json_output)])

            return ToolCommand(
                command=command,
                action="brute_force",
                evidence_title=f"DNSRecon brute force: {domain}",
                evidence_relative_dir="recon/dnsrecon/brute_force",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "domain": domain, "wordlist": wordlist, "json_output": json_output},
            )

        if action == "reverse_lookup":
            cidr = kwargs.get("cidr")
            if cidr is None and isinstance(target, Target):
                cidr = target.tool_value()
            cidr = self._string_value(cidr, "cidr")
            command = ["dnsrecon", "-r", cidr]
            json_output = kwargs.get("json_output")
            if json_output:
                command.extend(["-j", str(json_output)])

            return ToolCommand(
                command=command,
                action="reverse_lookup",
                evidence_title=f"DNSRecon reverse lookup: {cidr}",
                evidence_relative_dir="recon/dnsrecon/reverse_lookup",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "cidr": cidr, "json_output": json_output},
            )

        raise ValueError(f"Unsupported DNSRecon action: {action}")

    @classmethod
    def _domain_from_target_or_kwargs(cls, target: Target | str | None, kwargs: dict[str, Any]) -> str:
        """Resolve domain from explicit kwarg or Target."""

        explicit = kwargs.get("domain")
        if explicit is not None:
            return cls._string_value(explicit, "domain")
        if isinstance(target, Target):
            return cls._string_value(target.tool_value(), "domain")
        return cls._required_string(kwargs, "domain")

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
