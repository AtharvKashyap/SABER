"""Lateral movement planning wrapper for SABER.

This wrapper builds commands for planning, ranking, and exporting candidate
movement paths. It does not directly execute remote movement; it prepares and
records movement plans that agents/operators can inspect and chain later.
"""

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


class LateralMovementPlannerWrapper(BaseToolWrapper):
    """Wrapper for candidate lateral movement path planning."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize lateral movement planner wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="lateral_movement_planner",
                image="saber/lateral-movement:latest",
                phase=AssessmentPhase.LATERAL_MOVEMENT,
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                requested_by="LateralMovementPlannerWrapper",
                default_timeout_seconds=300,
                default_metadata={
                    "tool_family": "lateral_movement",
                    "tool": "planner",
                    "mode": "planning",
                },
            ),
        )

    def plan_paths(
        self,
        target: Target,
        session: MissionSession,
        source: str,
        graph_path: str | None = None,
        max_depth: int = 4,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Build candidate movement paths from a source to target."""

        return self.run(
            target=target,
            session=session,
            action="plan_paths",
            source=source,
            graph_path=graph_path,
            max_depth=max_depth,
            metadata=metadata,
        )

    def rank_paths(
        self,
        target: Target,
        session: MissionSession,
        candidate_paths_file: str,
        criteria: str = "lowest_risk",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Rank candidate movement paths by a chosen criterion."""

        return self.run(
            target=target,
            session=session,
            action="rank_paths",
            candidate_paths_file=candidate_paths_file,
            criteria=criteria,
            metadata=metadata,
        )

    def export_plan(
        self,
        target: Target,
        session: MissionSession,
        plan_id: str,
        output_format: str = "json",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Export a movement plan for reporting or review."""

        return self.run(
            target=target,
            session=session,
            action="export_plan",
            plan_id=plan_id,
            output_format=output_format,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a planner ToolCommand.

        Supports direct calls like build_command(action="plan_paths", ...)
        and BaseToolWrapper calls like build_command(target, action="plan_paths", ...).
        """

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            **(kwargs.get("metadata") or {}),
        }

        if action == "plan_paths":
            source = self._required_string(kwargs, "source")
            max_depth = self._positive_int(kwargs.get("max_depth", 4), "max_depth")
            destination = target.tool_value() if isinstance(target, Target) else self._required_string(kwargs, "destination")

            command = [
                "python",
                "-m",
                "saber.tools.lateral_movement.plan",
                "plan-paths",
                "--source",
                source,
                "--target",
                destination,
                "--max-depth",
                str(max_depth),
            ]
            graph_path = kwargs.get("graph_path")
            if graph_path:
                command.extend(["--graph", str(graph_path)])

            return ToolCommand(
                command=command,
                action="plan_paths",
                evidence_title=f"Lateral movement path plan: {source} -> {destination}",
                evidence_relative_dir="lateral_movement/plan/paths",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "source": source, "target": destination, "max_depth": max_depth},
            )

        if action == "rank_paths":
            candidate_paths_file = self._required_string(kwargs, "candidate_paths_file")
            criteria = str(kwargs.get("criteria") or "lowest_risk").strip()

            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.plan",
                    "rank-paths",
                    "--input",
                    candidate_paths_file,
                    "--criteria",
                    criteria,
                ],
                action="rank_paths",
                evidence_title=f"Lateral movement path ranking: {candidate_paths_file}",
                evidence_relative_dir="lateral_movement/plan/rank",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "candidate_paths_file": candidate_paths_file, "criteria": criteria},
            )

        if action == "export_plan":
            plan_id = self._required_string(kwargs, "plan_id")
            output_format = str(kwargs.get("output_format") or "json").strip().lower()
            if output_format not in {"json", "md", "html"}:
                raise ValueError("output_format must be one of: json, md, html")

            return ToolCommand(
                command=[
                    "python",
                    "-m",
                    "saber.tools.lateral_movement.plan",
                    "export-plan",
                    "--plan-id",
                    plan_id,
                    "--format",
                    output_format,
                ],
                action="export_plan",
                evidence_title=f"Lateral movement plan export: {plan_id}",
                evidence_relative_dir="lateral_movement/plan/export",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "plan_id": plan_id, "output_format": output_format},
            )

        raise ValueError(f"Unsupported lateral movement planning action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string argument."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _positive_int(value: Any, key: str) -> int:
        """Validate a positive integer argument."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return parsed
