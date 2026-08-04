"""Lateral movement path validation wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory

# NO CONTRACT — deliberately not exposed to the decider.
#
# These actions build ["python", "-m", "saber.tools.lateral_movement.<mod>", ...],
# which cannot run: Kali has no `python` alias, the saber package is not installed in
# the sandbox image, and this module has no __main__ (it prints nothing). The parsers
# that existed for it round-tripped an INVENTED JSON schema that no producer emits.
#
# Rather than advertise three tools that always fail — burning mission steps and
# tripping the repeated-failure guard — the CONTRACT is withheld, so ToolCatalog skips
# the wrapper (F0.4 behaviour for contractless wrappers). The class and its
# build_command are retained for whoever wants to finish the job properly: that needs a
# real __main__ emitting documented JSON, the saber package present in the image, and
# python3 rather than python. Lateral-movement *reasoning* is now the decider's job
# (F8), which reads MissionState directly instead of shelling out to a stateless
# container.


class PathValidationWrapper(BaseToolWrapper):
    """Wrapper for validating candidate lateral movement paths."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize path validation wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="path_validation",
                image="saber/lateral-movement:latest",
                phase=AssessmentPhase.LATERAL_MOVEMENT,
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                requested_by="PathValidationWrapper",
                default_timeout_seconds=300,
                default_metadata={
                    "tool_family": "lateral_movement",
                    "tool": "path_validation",
                    "mode": "validation",
                },
            ),
        )

    def validate_step(
        self,
        target: Target,
        session: MissionSession,
        source: str,
        technique: str,
        credential_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Validate one proposed path step."""

        return self.run(
            target=target,
            session=session,
            action="validate_step",
            source=source,
            technique=technique,
            credential_ref=credential_ref,
            metadata=metadata,
        )

    def validate_path(
        self,
        target: Target,
        session: MissionSession,
        path_file: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Validate a whole candidate path file."""

        return self.run(
            target=target,
            session=session,
            action="validate_path",
            path_file=path_file,
            metadata=metadata,
        )

    def dry_run_path_requires_authorization(
        self,
        target: Target,
        session: MissionSession,
        path_file: str,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Prepare a dry-run validation for a candidate path."""

        return self.run(
            target=target,
            session=session,
            action="dry_run_path",
            path_file=path_file,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a path-validation ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            **(kwargs.get("metadata") or {}),
        }

        if action == "validate_step":
            source = self._required_string(kwargs, "source")
            technique = self._required_string(kwargs, "technique")
            destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")

            command = [
                "python",
                "-m",
                "saber.tools.lateral_movement.path_validation",
                "validate-step",
                "--source",
                source,
                "--target",
                destination,
                "--technique",
                technique,
            ]
            if kwargs.get("credential_ref"):
                command.extend(["--credential-ref", str(kwargs["credential_ref"])])

            return ToolCommand(
                command=command,
                action="validate_step",
                evidence_title=f"Path step validation: {source} -> {destination}",
                evidence_relative_dir="lateral_movement/path_validation/step",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "source": source,
                    "target": destination,
                    "technique": technique,
                    "credential_ref": kwargs.get("credential_ref"),
                },
            )

        if action == "validate_path":
            path_file = self._required_string(kwargs, "path_file")
            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.path_validation",
                    "validate-path",
                    "--input",
                    path_file,
                ],
                action="validate_path",
                evidence_title=f"Path validation: {path_file}",
                evidence_relative_dir="lateral_movement/path_validation/path",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "path_file": path_file},
            )

        if action == "dry_run_path":
            path_file = self._required_string(kwargs, "path_file")
            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.path_validation",
                    "dry-run-path",
                    "--input",
                    path_file,
                ],
                action="dry_run_path",
                evidence_title=f"Path dry run: {path_file}",
                evidence_relative_dir="lateral_movement/path_validation/dry_run",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "path_file": path_file},
            )

        raise ValueError(f"Unsupported path-validation action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string argument."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
