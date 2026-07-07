"""OpenVAS/GVM API wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class OpenVASApiWrapper(BaseToolWrapper):
    """Wrapper for OpenVAS/GVM API-style scan commands."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize OpenVAS API wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="openvas_api",
                image="saber/openvas-api:latest",
                phase=AssessmentPhase.NETWORK,
                category=RequestedActionCategory.NETWORK,
                requested_by="OpenVASApiWrapper",
                default_timeout_seconds=900,
                default_metadata={"tool_family": "network", "tool": "openvas_api"},
            ),
        )

    def create_target(
        self,
        target: Target,
        session: MissionSession,
        name: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Create an OpenVAS target."""

        return self.run(target=target, session=session, action="create_target", name=name, metadata=metadata)

    def create_task(
        self,
        target: Target,
        session: MissionSession,
        target_id: str,
        scan_config_id: str,
        name: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Create an OpenVAS scan task."""

        return self.run(
            target=target,
            session=session,
            action="create_task",
            target_id=target_id,
            scan_config_id=scan_config_id,
            name=name,
            metadata=metadata,
        )

    def start_task(
        self,
        target: Target,
        session: MissionSession,
        task_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Start an OpenVAS scan task."""

        return self.run(target=target, session=session, action="start_task", task_id=task_id, metadata=metadata)

    def get_report(
        self,
        target: Target,
        session: MissionSession,
        report_id: str,
        output_format: str = "xml",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Download an OpenVAS report."""

        return self.run(
            target=target,
            session=session,
            action="get_report",
            report_id=report_id,
            output_format=output_format,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build an OpenVAS API ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        destination = target.tool_value() if isinstance(target, Target) else kwargs.get("destination")
        metadata = {"action": action, "target": destination, **(kwargs.get("metadata") or {})}

        if action == "create_target":
            name = self._required_string(kwargs, "name")
            if not destination:
                destination = self._required_string(kwargs, "destination")
            command = ["openvas-cli", "target-create", "--name", name, "--hosts", str(destination)]
            relative_dir = "network/openvas_api/create_target"
            title = f"OpenVAS create target: {name}"

        elif action == "create_task":
            name = self._required_string(kwargs, "name")
            target_id = self._required_string(kwargs, "target_id")
            scan_config_id = self._required_string(kwargs, "scan_config_id")
            command = [
                "openvas-cli",
                "task-create",
                "--name",
                name,
                "--target-id",
                target_id,
                "--scan-config-id",
                scan_config_id,
            ]
            relative_dir = "network/openvas_api/create_task"
            title = f"OpenVAS create task: {name}"
            metadata = {**metadata, "target_id": target_id, "scan_config_id": scan_config_id}

        elif action == "start_task":
            task_id = self._required_string(kwargs, "task_id")
            command = ["openvas-cli", "task-start", "--task-id", task_id]
            relative_dir = "network/openvas_api/start_task"
            title = f"OpenVAS start task: {task_id}"
            metadata = {**metadata, "task_id": task_id}

        elif action == "get_report":
            report_id = self._required_string(kwargs, "report_id")
            output_format = self._required_string(kwargs, "output_format").lower()
            if output_format not in {"xml", "json", "pdf"}:
                raise ValueError("output_format must be one of: xml, json, pdf")
            command = ["openvas-cli", "report-get", "--report-id", report_id, "--format", output_format]
            relative_dir = "network/openvas_api/get_report"
            title = f"OpenVAS report: {report_id}"
            metadata = {**metadata, "report_id": report_id, "output_format": output_format}

        else:
            raise ValueError(f"Unsupported OpenVAS API action: {action}")

        return ToolCommand(
            command=command,
            action=action,
            evidence_title=title,
            evidence_relative_dir=relative_dir,
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata=metadata,
        )

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
