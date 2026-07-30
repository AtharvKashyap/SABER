"""Lateral movement path validation wrapper for SABER."""

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
    tool_name="path_validation",
    category="lateral_movement",
    phase="lateral_movement",
    description=(
        "Validate candidate lateral movement path steps against known state and, for "
        "dry runs, against the live target."
    ),
    parser="path_validation",
    actions=(
        ActionContract(
            action="validate_step",
            description="Validate a single proposed path step against known state.",
            args=(
                ArgSpec("source", "str", required=True, description="Source host/label."),
                ArgSpec(
                    "technique", "str", required=True,
                    description="Movement technique, e.g. psexec/wmiexec/ssh.",
                ),
                ArgSpec(
                    "credential_ref", "str", required=False, default=None,
                    description="Reference to a known credential to validate against.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"source": "WKSTN01", "technique": "psexec"},
        ),
        ActionContract(
            action="validate_path",
            description="Validate every hop of a candidate path file against known state.",
            args=(
                ArgSpec(
                    "path_file", "str", required=True,
                    description="Evidence-relative path to a candidate path artifact.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"path_file": "lateral_movement/plan/paths/candidates.json"},
        ),
        ActionContract(
            action="dry_run_path",
            description=(
                "Dry-run a candidate path against the live target to confirm each hop is "
                "actually reachable. Touches the remote host."
            ),
            args=(
                ArgSpec(
                    "path_file", "str", required=True,
                    description="Evidence-relative path to a candidate path artifact.",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={"path_file": "lateral_movement/plan/paths/candidates.json"},
        ),
    ),
)


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
