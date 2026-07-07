"""NetExec wrapper for SABER Active Directory and SMB enumeration.

NetExec is powerful and can cross into intrusive behavior depending on flags.
This wrapper exposes safer authenticated enumeration methods first and marks
higher-risk checks as approval-required.
"""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.tools.capability import RequestedActionCategory
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig


class NetExecWrapper(BaseToolWrapper):
    """Wrapper for NetExec authenticated enumeration."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize the NetExec wrapper.

        Args:
            sandbox: Sandbox used for guarded execution.
            config: Optional wrapper configuration.
        """

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="netexec",
                image="saber/netexec:latest",
                phase=AssessmentPhase.ACTIVE_DIRECTORY,
                category=RequestedActionCategory.ACTIVE_DIRECTORY,
                requested_by="NetExecWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "active_directory", "tool": "netexec"},
            ),
        )

    def smb_auth_check(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
    ) -> SandboxExecutionResult:
        """Check SMB authentication against a target.

        Args:
            target: In-scope SMB target.
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
            action="smb_auth_check",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
        )

    def smb_shares(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
    ) -> SandboxExecutionResult:
        """Enumerate SMB shares.

        Args:
            target: In-scope SMB target.
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
            action="smb_shares",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
        )

    def ldap_users(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
    ) -> SandboxExecutionResult:
        """Enumerate LDAP users through NetExec.

        Args:
            target: In-scope LDAP/DC target.
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
            action="ldap_users",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
        )

    def local_admin_check_requires_approval(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
    ) -> SandboxExecutionResult:
        """Check local-admin access with explicit authorization.

        Args:
            target: In-scope SMB target.
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
            action="local_admin_check",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            requires_explicit_authorization=True,
        )

    def build_command(self, target: Target, **kwargs: Any) -> ToolCommand:
        """Build a NetExec command plan.

        Args:
            target: In-scope target.
            kwargs: Action-specific options.

        Returns:
            ToolCommand for BaseToolWrapper.
        """

        action = str(kwargs["action"])
        domain = str(kwargs["domain"])
        username = str(kwargs["username"])
        password_env_var = str(kwargs.get("password_env_var", "AD_PASSWORD"))
        requires_explicit_authorization = bool(kwargs.get("requires_explicit_authorization", False))

        target_value = target.tool_value()
        base_command = [
            "nxc",
            "smb" if action != "ldap_users" else "ldap",
            target_value,
            "-d",
            domain,
            "-u",
            username,
            "-p",
            f"${password_env_var}",
        ]

        if action == "smb_auth_check":
            command = base_command
            evidence_title = f"NetExec SMB auth check: {target.value}"
        elif action == "smb_shares":
            command = [*base_command, "--shares"]
            evidence_title = f"NetExec SMB shares: {target.value}"
        elif action == "ldap_users":
            command = [*base_command, "--users"]
            evidence_title = f"NetExec LDAP users: {target.value}"
        elif action == "local_admin_check":
            command = [*base_command, "--local-auth"]
            evidence_title = f"NetExec local-admin check: {target.value}"
            requires_explicit_authorization = True
        else:
            raise ValueError(f"Unsupported NetExec action: {action}")

        return ToolCommand(
            command=command,
            action=f"netexec_{action}",
            evidence_title=evidence_title,
            evidence_relative_dir="active_directory/netexec",
            requires_explicit_authorization=requires_explicit_authorization,
            environment={password_env_var: ""},
            runner_options={"requires_shell_expansion": True},
            metadata={
                "netexec_action": action,
                "domain": domain,
                "target": target.value,
                "password_env_var": password_env_var,
            },
        )
