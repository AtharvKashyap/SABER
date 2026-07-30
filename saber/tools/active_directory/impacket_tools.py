"""Impacket tool wrappers for SABER Active Directory workflows.

This module wraps selected Impacket utilities as typed Python methods for agents.
The methods build command plans and delegate execution through BaseToolWrapper.

Raw passwords should not be placed directly in command arguments. Use environment
variable placeholders or secret-reference based injection in the runner layer.
"""

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
    tool_name="impacket",
    category="active_directory",
    phase="active_directory",
    description=(
        "Impacket Active Directory utilities: user/SPN enumeration, AS-REP "
        "roasting candidate checks, and SMB remote-execution validation."
    ),
    parser="impacket",
    actions=(
        ActionContract(
            action="get_ad_users",
            description=(
                "Enumerate domain users via GetADUsers.py using authenticated "
                "credentials (identity built from domain/username/password_env_var)."
            ),
            args=(
                ArgSpec("domain", "str", required=True, description="AD domain, e.g. corp.local."),
                ArgSpec("username", "str", required=True, description="Authenticating username."),
                ArgSpec(
                    "password_env_var",
                    "str",
                    required=False,
                    default="AD_PASSWORD",
                    description="Env var holding the authenticating password.",
                ),
                ArgSpec(
                    "dc_ip",
                    "str",
                    required=False,
                    default=None,
                    description="Optional domain controller IP.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("account",),
            example_args={
                "domain": "corp.local",
                "username": "svc-recon",
                "password_env_var": "AD_PASSWORD",
            },
        ),
        ActionContract(
            action="get_spns",
            description=(
                "Enumerate Kerberoastable SPNs via GetUserSPNs.py; with "
                "request_tickets=True it also requests service tickets, yielding "
                "crackable $krb5tgs$ hashes."
            ),
            args=(
                ArgSpec("domain", "str", required=True, description="AD domain, e.g. corp.local."),
                ArgSpec("username", "str", required=True, description="Authenticating username."),
                ArgSpec(
                    "password_env_var",
                    "str",
                    required=False,
                    default="AD_PASSWORD",
                    description="Env var holding the authenticating password.",
                ),
                ArgSpec(
                    "dc_ip",
                    "str",
                    required=False,
                    default=None,
                    description="Optional domain controller IP.",
                ),
                ArgSpec(
                    "request_tickets",
                    "bool",
                    required=False,
                    default=False,
                    description="Request service tickets (-request) to obtain crackable hashes.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("credential",),
            example_args={
                "domain": "corp.local",
                "username": "svc-recon",
                "password_env_var": "AD_PASSWORD",
                "request_tickets": True,
            },
        ),
        ActionContract(
            action="get_asrep_candidates",
            description=(
                "Check AS-REP roastable candidates from an approved username file "
                "via GetNPUsers.py (-no-pass); yields crackable $krb5asrep$ hashes."
            ),
            args=(
                ArgSpec("domain", "str", required=True, description="AD domain, e.g. corp.local."),
                ArgSpec(
                    "username_file",
                    "str",
                    required=True,
                    description="Path to an approved username list evidence/input file.",
                ),
                ArgSpec(
                    "dc_ip",
                    "str",
                    required=False,
                    default=None,
                    description="Optional domain controller IP.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("credential",),
            example_args={"domain": "corp.local", "username_file": "/evidence/usernames.txt"},
        ),
        ActionContract(
            action="smb_exec_check",
            description=(
                "Validate remote SMB code execution via psexec.py by running "
                "'whoami' against the target; confirms a usable exec foothold."
            ),
            args=(
                ArgSpec("domain", "str", required=True, description="AD domain, e.g. corp.local."),
                ArgSpec("username", "str", required=True, description="Authenticating username."),
                ArgSpec(
                    "password_env_var",
                    "str",
                    required=False,
                    default="AD_PASSWORD",
                    description="Env var holding the authenticating password.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("session",),
            example_args={"domain": "corp.local", "username": "administrator"},
        ),
    ),
)


class ImpacketToolsWrapper(BaseToolWrapper):
    """Wrapper for selected Impacket Active Directory utilities."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize the Impacket wrapper.

        Args:
            sandbox: Sandbox used for guarded execution.
            config: Optional wrapper configuration.
        """

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="impacket",
                image="saber/impacket:latest",
                phase=AssessmentPhase.ACTIVE_DIRECTORY,
                category=RequestedActionCategory.ACTIVE_DIRECTORY,
                requested_by="ImpacketToolsWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "active_directory", "tool": "impacket"},
            ),
        )

    def get_ad_users(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
        dc_ip: str | None = None,
    ) -> SandboxExecutionResult:
        """Enumerate AD users using Impacket GetADUsers.

        Args:
            target: In-scope AD target.
            session: Current mission session.
            domain: AD domain.
            username: Username.
            password_env_var: Environment variable containing password.
            dc_ip: Optional domain controller IP.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="get_ad_users",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            dc_ip=dc_ip,
        )

    def get_spns(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
        dc_ip: str | None = None,
        request_tickets: bool = False,
    ) -> SandboxExecutionResult:
        """Enumerate SPNs using Impacket GetUserSPNs.

        Args:
            target: In-scope AD target.
            session: Current mission session.
            domain: AD domain.
            username: Username.
            password_env_var: Environment variable containing password.
            dc_ip: Optional domain controller IP.
            request_tickets: Whether to request service tickets.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="get_spns",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            dc_ip=dc_ip,
            request_tickets=request_tickets,
            requires_explicit_authorization=request_tickets,
        )

    def get_asrep_candidates(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username_file: str,
        dc_ip: str | None = None,
    ) -> SandboxExecutionResult:
        """Check AS-REP roastable candidates from an approved username file.

        Args:
            target: In-scope AD target.
            session: Current mission session.
            domain: AD domain.
            username_file: Path to username file evidence/input.
            dc_ip: Optional domain controller IP.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="get_asrep_candidates",
            domain=domain,
            username_file=username_file,
            dc_ip=dc_ip,
            requires_explicit_authorization=True,
        )

    def smb_exec_check_requires_approval(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
    ) -> SandboxExecutionResult:
        """Build an approval-required remote execution validation command.

        Args:
            target: In-scope host target.
            session: Current mission session.
            domain: AD domain.
            username: Username.
            password_env_var: Environment variable containing password.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="smb_exec_check",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            requires_explicit_authorization=True,
        )

    def build_command(self, target: Target, **kwargs: Any) -> ToolCommand:
        """Build an Impacket command plan.

        Args:
            target: In-scope target.
            kwargs: Action-specific options.

        Returns:
            ToolCommand for BaseToolWrapper.
        """

        action = str(kwargs["action"])

        if action == "get_ad_users":
            return self._build_get_ad_users(target, **kwargs)
        if action == "get_spns":
            return self._build_get_spns(target, **kwargs)
        if action == "get_asrep_candidates":
            return self._build_get_asrep_candidates(target, **kwargs)
        if action == "smb_exec_check":
            return self._build_smb_exec_check(target, **kwargs)

        raise ValueError(f"Unsupported Impacket action: {action}")

    def _identity(self, domain: str, username: str, password_env_var: str) -> str:
        """Build an Impacket identity string using an environment placeholder."""

        return f"{domain}/{username}:${password_env_var}"

    def _build_get_ad_users(self, target: Target, **kwargs: Any) -> ToolCommand:
        domain = str(kwargs["domain"])
        username = str(kwargs["username"])
        password_env_var = str(kwargs.get("password_env_var", "AD_PASSWORD"))
        dc_ip = kwargs.get("dc_ip")

        identity = self._identity(domain, username, password_env_var)
        command = ["impacket-GetADUsers", identity, "-all"]
        if dc_ip:
            command.extend(["-dc-ip", str(dc_ip)])

        return ToolCommand(
            command=command,
            action="impacket_get_ad_users",
            evidence_title=f"Impacket GetADUsers: {domain}",
            evidence_relative_dir="active_directory/impacket",
            environment={password_env_var: ""},
            runner_options={"requires_shell_expansion": True},
            metadata={"impacket_action": "get_ad_users", "domain": domain, "target": target.value},
        )

    def _build_get_spns(self, target: Target, **kwargs: Any) -> ToolCommand:
        domain = str(kwargs["domain"])
        username = str(kwargs["username"])
        password_env_var = str(kwargs.get("password_env_var", "AD_PASSWORD"))
        dc_ip = kwargs.get("dc_ip")
        request_tickets = bool(kwargs.get("request_tickets", False))
        requires_explicit_authorization = bool(kwargs.get("requires_explicit_authorization", request_tickets))

        command = ["impacket-GetUserSPNs", self._identity(domain, username, password_env_var)]
        if request_tickets:
            command.append("-request")
        if dc_ip:
            command.extend(["-dc-ip", str(dc_ip)])

        return ToolCommand(
            command=command,
            action="impacket_get_spns",
            evidence_title=f"Impacket GetUserSPNs: {domain}",
            evidence_relative_dir="active_directory/impacket",
            requires_explicit_authorization=requires_explicit_authorization,
            environment={password_env_var: ""},
            runner_options={"requires_shell_expansion": True},
            metadata={
                "impacket_action": "get_spns",
                "domain": domain,
                "target": target.value,
                "request_tickets": request_tickets,
            },
        )

    def _build_get_asrep_candidates(self, target: Target, **kwargs: Any) -> ToolCommand:
        domain = str(kwargs["domain"])
        username_file = str(kwargs["username_file"])
        dc_ip = kwargs.get("dc_ip")

        command = ["impacket-GetNPUsers", domain, "-usersfile", username_file, "-no-pass"]
        if dc_ip:
            command.extend(["-dc-ip", str(dc_ip)])

        return ToolCommand(
            command=command,
            action="impacket_get_asrep_candidates",
            evidence_title=f"Impacket GetNPUsers candidates: {domain}",
            evidence_relative_dir="active_directory/impacket",
            requires_explicit_authorization=True,
            metadata={
                "impacket_action": "get_asrep_candidates",
                "domain": domain,
                "target": target.value,
                "username_file": username_file,
            },
        )

    def _build_smb_exec_check(self, target: Target, **kwargs: Any) -> ToolCommand:
        domain = str(kwargs["domain"])
        username = str(kwargs["username"])
        password_env_var = str(kwargs.get("password_env_var", "AD_PASSWORD"))

        command = [
            "impacket-psexec",
            self._identity(domain, username, password_env_var),
            f"@{target.tool_value()}",
            "whoami",
        ]

        return ToolCommand(
            command=command,
            action="impacket_smb_exec_check",
            evidence_title=f"Impacket SMB execution check: {target.value}",
            evidence_relative_dir="active_directory/impacket",
            requires_explicit_authorization=True,
            environment={password_env_var: ""},
            runner_options={"requires_shell_expansion": True},
            metadata={"impacket_action": "smb_exec_check", "domain": domain, "target": target.value},
        )
