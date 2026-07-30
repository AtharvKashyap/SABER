"""Lateral movement session-check wrapper for SABER.

This wrapper validates known session/access context and records evidence about
whether a candidate step has the prerequisites it claims to have.
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
    tool_name="session_checks",
    category="lateral_movement",
    phase="lateral_movement",
    description=(
        "Validate and summarize known session/access records. Only validate_session may "
        "confirm a live interactive foothold; reachability alone is never recorded as a "
        "session."
    ),
    parser="session_checks",
    actions=(
        ActionContract(
            action="validate_session",
            description="Validate that a known session/access record is still usable.",
            args=(
                ArgSpec("session_id", "str", required=True),
                ArgSpec("expected_user", "str", required=False, default=None),
                ArgSpec("protocol", "str", required=False, default=None),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("session", "note"),
            example_args={"session_id": "sess-1001", "protocol": "ssh"},
        ),
        ActionContract(
            action="summarize_sessions",
            description="Summarize known session/access records from a local artifact.",
            args=(
                ArgSpec(
                    "sessions_file", "str", required=True,
                    description="Evidence-relative path to a sessions record artifact.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"sessions_file": "lateral_movement/session_checks/sessions.json"},
        ),
        ActionContract(
            action="authenticated_reachability",
            description=(
                "Check whether a source can reach the target using a known credential. "
                "Touches the remote host; proves reachability only, never a foothold."
            ),
            args=(
                ArgSpec("source", "str", required=True),
                ArgSpec("protocol", "str", required=True, description="e.g. smb/ssh/winrm."),
                ArgSpec("credential_ref", "str", required=True),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={"source": "WKSTN01", "protocol": "smb", "credential_ref": "cred-42"},
        ),
    ),
)


class SessionChecksWrapper(BaseToolWrapper):
    """Wrapper for validating session and access context."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize session checks wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="session_checks",
                image="saber/lateral-movement:latest",
                phase=AssessmentPhase.LATERAL_MOVEMENT,
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                requested_by="SessionChecksWrapper",
                default_timeout_seconds=300,
                default_metadata={
                    "tool_family": "lateral_movement",
                    "tool": "session_checks",
                    "mode": "validation",
                },
            ),
        )

    def validate_session(
        self,
        target: Target,
        session: MissionSession,
        session_id: str,
        expected_user: str | None = None,
        protocol: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Validate that a known session/access record is usable."""

        return self.run(
            target=target,
            session=session,
            action="validate_session",
            session_id=session_id,
            expected_user=expected_user,
            protocol=protocol,
            metadata=metadata,
        )

    def summarize_sessions(
        self,
        target: Target,
        session: MissionSession,
        sessions_file: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Summarize known session/access records from a local artifact."""

        return self.run(
            target=target,
            session=session,
            action="summarize_sessions",
            sessions_file=sessions_file,
            metadata=metadata,
        )

    def check_authenticated_reachability_requires_authorization(
        self,
        target: Target,
        session: MissionSession,
        source: str,
        protocol: str,
        credential_ref: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Check whether a source can reach a target using a known credential reference."""

        return self.run(
            target=target,
            session=session,
            action="authenticated_reachability",
            source=source,
            protocol=protocol,
            credential_ref=credential_ref,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a session-check ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            **(kwargs.get("metadata") or {}),
        }
        target_value = target.tool_value() if isinstance(target, Target) else kwargs.get("target")

        if action == "validate_session":
            session_id = self._required_string(kwargs, "session_id")
            command = [
                "python",
                "-m",
                "saber.tools.lateral_movement.session_checks",
                "validate-session",
                "--session-id",
                session_id,
            ]
            if target_value:
                command.extend(["--target", str(target_value)])
            if kwargs.get("expected_user"):
                command.extend(["--expected-user", str(kwargs["expected_user"])])
            if kwargs.get("protocol"):
                command.extend(["--protocol", str(kwargs["protocol"])])

            return ToolCommand(
                command=command,
                action="validate_session",
                evidence_title=f"Session validation: {session_id}",
                evidence_relative_dir="lateral_movement/session_checks/validate",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "session_id": session_id,
                    "target": target_value,
                    "expected_user": kwargs.get("expected_user"),
                    "protocol": kwargs.get("protocol"),
                },
            )

        if action == "summarize_sessions":
            sessions_file = self._required_string(kwargs, "sessions_file")
            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.session_checks",
                    "summarize-sessions",
                    "--input",
                    sessions_file,
                ],
                action="summarize_sessions",
                evidence_title=f"Session summary: {sessions_file}",
                evidence_relative_dir="lateral_movement/session_checks/summary",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "sessions_file": sessions_file},
            )

        if action == "authenticated_reachability":
            source = self._required_string(kwargs, "source")
            protocol = self._required_string(kwargs, "protocol")
            credential_ref = self._required_string(kwargs, "credential_ref")
            destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")

            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.session_checks",
                    "authenticated-reachability",
                    "--source",
                    source,
                    "--target",
                    destination,
                    "--protocol",
                    protocol,
                    "--credential-ref",
                    credential_ref,
                ],
                action="authenticated_reachability",
                evidence_title=f"Authenticated reachability: {source} -> {destination}",
                evidence_relative_dir="lateral_movement/session_checks/reachability",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "source": source,
                    "target": destination,
                    "protocol": protocol,
                    "credential_ref": credential_ref,
                },
            )

        raise ValueError(f"Unsupported session-check action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string argument."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
