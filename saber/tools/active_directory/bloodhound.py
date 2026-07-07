"""BloodHound wrapper for SABER Active Directory collection.

This wrapper exposes BloodHound collection as agent-callable Python methods while
keeping execution inside SABER's normal safety path:

    Agent / MissionController
        -> BloodHoundWrapper.collect(...)
        -> ToolCommand
        -> SandboxExecutionRequest
        -> Sandbox / Runner / EvidenceStore

The wrapper returns SandboxExecutionResult for now. Later, a BloodHound parser
should turn saved JSON/ZIP output into AD graph models.
"""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.tools.capability import RequestedActionCategory
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig


DEFAULT_BLOODHOUND_COLLECTION_METHODS = [
    "DCOnly",
    "Group",
    "LocalAdmin",
    "Session",
    "Trusts",
]


class BloodHoundWrapper(BaseToolWrapper):
    """Wrapper for BloodHound / bloodhound-python collection workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize the BloodHound wrapper.

        Args:
            sandbox: Sandbox used for guarded execution.
            config: Optional wrapper configuration.
        """

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="bloodhound",
                image="saber/bloodhound-python:latest",
                phase=AssessmentPhase.ACTIVE_DIRECTORY,
                category=RequestedActionCategory.ACTIVE_DIRECTORY,
                requested_by="BloodHoundWrapper",
                default_timeout_seconds=1800,
                default_metadata={"tool_family": "active_directory", "tool": "bloodhound"},
            ),
        )

    def collect(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
        collection_methods: list[str] | None = None,
        nameserver: str | None = None,
        dc_host: str | None = None,
        output_prefix: str = "bloodhound",
        requires_explicit_authorization: bool = True,
    ) -> SandboxExecutionResult:
        """Collect BloodHound-compatible AD data.

        Args:
            target: In-scope AD domain controller or domain target.
            session: Current mission session.
            domain: AD domain name.
            username: Username for authenticated collection.
            password_env_var: Environment variable name containing the password.
            collection_methods: BloodHound collection methods.
            nameserver: Optional DNS server.
            dc_host: Optional domain controller hostname.
            output_prefix: Output prefix for generated files.
            requires_explicit_authorization: Whether collection requires approval.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="collect",
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            collection_methods=collection_methods or DEFAULT_BLOODHOUND_COLLECTION_METHODS,
            nameserver=nameserver,
            dc_host=dc_host,
            output_prefix=output_prefix,
            requires_explicit_authorization=requires_explicit_authorization,
        )

    def collect_safe_defaults(
        self,
        target: Target,
        session: MissionSession,
        domain: str,
        username: str,
        password_env_var: str = "AD_PASSWORD",
        nameserver: str | None = None,
        dc_host: str | None = None,
    ) -> SandboxExecutionResult:
        """Run a constrained default BloodHound collection.

        Args:
            target: In-scope AD target.
            session: Current mission session.
            domain: AD domain name.
            username: Username for authenticated collection.
            password_env_var: Environment variable name containing the password.
            nameserver: Optional DNS server.
            dc_host: Optional domain controller hostname.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.collect(
            target=target,
            session=session,
            domain=domain,
            username=username,
            password_env_var=password_env_var,
            collection_methods=["DCOnly", "Group", "Trusts"],
            nameserver=nameserver,
            dc_host=dc_host,
            output_prefix="bloodhound_safe",
            requires_explicit_authorization=False,
        )

    def ingest_existing_zip(
        self,
        target: Target,
        session: MissionSession,
        zip_path: str,
    ) -> SandboxExecutionResult:
        """Register an existing BloodHound ZIP for later parser ingestion.

        Args:
            target: Associated AD target.
            session: Current mission session.
            zip_path: Path to an existing BloodHound collection archive.

        Returns:
            SandboxExecutionResult from Sandbox.
        """

        return self.run(
            target=target,
            session=session,
            action="ingest_existing_zip",
            zip_path=zip_path,
            requires_explicit_authorization=False,
        )

    def build_command(self, target: Target, **kwargs: Any) -> ToolCommand:
        """Build a BloodHound command plan.

        Args:
            target: In-scope AD target.
            kwargs: Action-specific options.

        Returns:
            ToolCommand for BaseToolWrapper.
        """

        action = str(kwargs.get("action", "collect"))

        if action == "ingest_existing_zip":
            zip_path = str(kwargs["zip_path"])
            return ToolCommand(
                command=["python", "-m", "saber.parsers.bloodhound", "ingest", zip_path],
                action="bloodhound_ingest_existing_zip",
                evidence_title=f"BloodHound ingest: {zip_path}",
                evidence_relative_dir="active_directory/bloodhound",
                requires_explicit_authorization=False,
                metadata={"bloodhound_action": action, "zip_path": zip_path},
            )

        domain = str(kwargs["domain"])
        username = str(kwargs["username"])
        password_env_var = str(kwargs.get("password_env_var", "AD_PASSWORD"))
        collection_methods = kwargs.get("collection_methods") or DEFAULT_BLOODHOUND_COLLECTION_METHODS
        nameserver = kwargs.get("nameserver")
        dc_host = kwargs.get("dc_host")
        output_prefix = str(kwargs.get("output_prefix", "bloodhound"))
        requires_explicit_authorization = bool(kwargs.get("requires_explicit_authorization", True))

        command = [
            "bloodhound-python",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            f"${password_env_var}",
            "-c",
            ",".join(collection_methods),
            "--zip",
            "-op",
            output_prefix,
        ]

        if nameserver:
            command.extend(["-ns", str(nameserver)])
        if dc_host:
            command.extend(["-dc", str(dc_host)])

        return ToolCommand(
            command=command,
            action="bloodhound_collect",
            evidence_title=f"BloodHound collection: {domain}",
            evidence_relative_dir="active_directory/bloodhound",
            requires_explicit_authorization=requires_explicit_authorization,
            environment={password_env_var: ""},
            runner_options={"requires_shell_expansion": True},
            metadata={
                "bloodhound_action": action,
                "domain": domain,
                "target": target.value,
                "collection_methods": collection_methods,
                "password_env_var": password_env_var,
                "output_prefix": output_prefix,
            },
        )
