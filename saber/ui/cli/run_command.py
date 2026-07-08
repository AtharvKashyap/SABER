"""CLI mission run command for SABER."""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from saber.agents.base_agent import AgentObservation
from saber.core.runtime import SaberConfig, SaberRuntime, build_saber_runtime
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionPlan
from saber.orchestration.mission_orchestrator import MissionRunResult


PROFILE_AGENTS: dict[str, set[str]] = {
    "recon": {"planner_agent", "recon_agent", "reporter_agent"},
    "web": {"planner_agent", "recon_agent", "web_agent", "reporter_agent"},
    "network": {"planner_agent", "recon_agent", "network_agent", "reporter_agent"},
    "ad": {"planner_agent", "recon_agent", "network_agent", "lateral_movement_agent", "reporter_agent"},
    "full": {
        "planner_agent",
        "recon_agent",
        "network_agent",
        "web_agent",
        "exploit_agent",
        "post_exploit_agent",
        "lateral_movement_agent",
        "reverse_engineer_agent",
        "reporter_agent",
    },
}


def run_cli_mission(
    *,
    target_value: str,
    profile: str = "recon",
    mission_name: str | None = None,
    objective: str | None = None,
    db_path: str = "runs/saber.db",
    evidence_dir: str = "runs/evidence",
    reports_dir: str = "runs/reports",
    require_approval: bool = True,
    max_steps: int = 50,
    dry_run: bool = False,
    agent_mode: str = "deterministic",
) -> dict[str, Any]:
    """Run a SABER mission from the CLI and persist the result."""

    normalized_profile = profile.strip().lower()
    if normalized_profile not in PROFILE_AGENTS:
        raise ValueError(f"Unsupported profile: {profile}. Expected one of: {', '.join(sorted(PROFILE_AGENTS))}")

    session_id = f"session_{uuid4().hex[:12]}"
    resolved_mission_name = mission_name or f"SABER {normalized_profile} mission for {target_value}"
    resolved_objective = objective or _objective_for_profile(normalized_profile, target_value)

    config = SaberConfig(
        db_path=_path(db_path),
        evidence_dir=_path(evidence_dir),
        reports_dir=_path(reports_dir),
        profile=normalized_profile,
        require_approval=require_approval,
        max_steps=max_steps,
        agent_mode=agent_mode,
        metadata={"source": "cli_run"},
    )

    mission_started_at = time.time()
    runtime = build_saber_runtime(config)

    try:
        session = _make_session(session_id, resolved_mission_name, target_value, normalized_profile, dry_run)
        target = _make_target(target_value)

        runtime.session_store.create_session(
            {
                "session_id": session_id,
                "mission_name": resolved_mission_name,
                "status": "running",
                "metadata": {
                    "target": target_value,
                    "profile": normalized_profile,
                    "objective": resolved_objective,
                    "dry_run": dry_run,
                    "require_approval": require_approval,
                    "agent_mode": agent_mode,
                    "started_at": datetime.now(UTC).isoformat(),
                },
            }
        )

        plan = runtime.orchestrator.create_plan(
            mission_name=resolved_mission_name,
            target=target,
            objective=resolved_objective,
            metadata={
                "profile": normalized_profile,
                "dry_run": dry_run,
                "require_approval": require_approval,
            },
        )
        plan = filter_plan_for_profile(plan, normalized_profile)

        runtime.session_store.save_plan(session_id, plan)

        pre_report_plan, report_plan = split_plan_for_reporting(plan)

        total_records = 0
        final_status = "completed"

        if report_plan is None:
            result = runtime.orchestrator.run_mission(
                session=session,
                target=target,
                objective=resolved_objective,
                plan=pre_report_plan,
                constraints={
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                    "require_approval": require_approval,
                },
                metadata={
                    "source": "cli_run",
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                },
            )

            persist_mission_result(
                runtime,
                result,
                mission_started_at=mission_started_at,
                process_evidence=True,
                save_plan=True,
            )
            total_records += len(result.records)
            final_status = str(result.status.value if hasattr(result.status, "value") else result.status)
        else:
            pre_result = runtime.orchestrator.run_mission(
                session=session,
                target=target,
                objective=resolved_objective,
                plan=pre_report_plan,
                constraints={
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                    "require_approval": require_approval,
                    "phase": "pre_report",
                },
                metadata={
                    "source": "cli_run",
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                    "phase": "pre_report",
                },
            )

            # This is the important ordering change:
            # persist pre-report observations/evidence, then parse evidence,
            # then run the reporter with the parsed observations included.
            persist_mission_result(
                runtime,
                pre_result,
                mission_started_at=mission_started_at,
                process_evidence=True,
                save_plan=True,
            )
            total_records += len(pre_result.records)

            report_observations = _load_observations_for_reporter(
                runtime,
                session_id,
                fallback_observations=pre_result.observations,
            )

            report_result = runtime.orchestrator.run_mission(
                session=session,
                target=target,
                objective="Generate evidence-backed assessment report from parsed observations.",
                plan=report_plan,
                initial_observations=report_observations,
                constraints={
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                    "require_approval": require_approval,
                    "phase": "report",
                },
                metadata={
                    "source": "cli_run",
                    "profile": normalized_profile,
                    "dry_run": dry_run,
                    "phase": "report",
                    "parsed_observation_count": len(report_observations),
                },
            )

            persist_mission_result(
                runtime,
                report_result,
                mission_started_at=mission_started_at,
                process_evidence=False,
                save_plan=False,
                save_observations=False,
            )
            total_records += len(report_result.records)
            final_status = str(
                report_result.status.value if hasattr(report_result.status, "value") else report_result.status
            )

        stored_observations = _safe_count(lambda: runtime.finding_store.list_observations(session_id))
        stored_evidence = _safe_count(lambda: runtime.evidence_index.list_evidence(session_id))
        stored_steps = _safe_count(lambda: runtime.session_store.list_steps(session_id))

        return {
            "session_id": session_id,
            "mission_name": resolved_mission_name,
            "target": target_value,
            "profile": normalized_profile,
            "status": final_status,
            "steps": stored_steps,
            "records": total_records,
            "observations": stored_observations,
            "evidence": stored_evidence,
            "dry_run": dry_run,
            "agent_mode": agent_mode,
            "llm_enabled": runtime.llm_client.enabled,
            "next_commands": [
                f"python -m saber.ui.cli.main sessions show {session_id}",
                f"python -m saber.ui.cli.main live {session_id} --once",
                f"python -m saber.ui.cli.main findings list {session_id}",
                f"python -m saber.ui.cli.main approvals list --session-id {session_id}",
            ],
        }
    except Exception:
        runtime.session_store.update_session_status(
            session_id,
            "failed",
            metadata={"failed_at": datetime.now(UTC).isoformat()},
        )
        raise
    finally:
        runtime.close()


def persist_mission_result(
    runtime: SaberRuntime,
    result: MissionRunResult,
    mission_started_at: float = 0.0,
    process_evidence: bool = True,
    save_plan: bool = True,
    save_observations: bool = True,
) -> None:
    """Persist an orchestrator result into storage."""

    session_id = result.session.session_id
    status = str(result.status.value if hasattr(result.status, "value") else result.status)

    runtime.session_store.update_session_status(
        session_id,
        status,
        metadata={
            "completed_at": datetime.now(UTC).isoformat(),
            "run_metadata": result.metadata,
        },
    )

    if save_plan:
        runtime.session_store.save_plan(session_id, result.plan)

    for step in result.plan.steps:
        runtime.session_store.save_step(session_id, step)

    for record in result.records:
        runtime.session_store.save_step_record(session_id, record)

        if record.requires_approval:
            decision = getattr(record.agent_result, "decision", None)
            runtime.session_store.create_approval_request(
                session_id=session_id,
                step_id=record.step_id,
                reason=getattr(decision, "message", None) or "Agent requested approval.",
                requested_action={
                    "agent_name": record.agent_name,
                    "step_id": record.step_id,
                    "decision": _safe_decision_dict(decision),
                },
                metadata={
                    "source": "orchestrator",
                    "record": record.to_dict(),
                },
            )

    if save_observations:
        for observation in result.observations:
            _save_agent_observation(runtime, session_id, observation)

    if process_evidence:
        _index_sandbox_evidence(runtime, session_id, mission_started_at=mission_started_at)


def filter_plan_for_profile(plan: ExecutionPlan, profile: str) -> ExecutionPlan:
    """Filter execution plan to profile-specific agents."""

    if profile == "full":
        return plan

    allowed_agents = PROFILE_AGENTS[profile]
    kept_steps = [step for step in plan.steps if step.agent_name in allowed_agents]
    kept_ids = {step.step_id for step in kept_steps}

    adjusted_steps = []
    for step in kept_steps:
        depends_on = [step_id for step_id in getattr(step, "depends_on", []) if step_id in kept_ids]
        try:
            adjusted_steps.append(replace(step, depends_on=depends_on))
        except TypeError:
            adjusted_steps.append(step)

    try:
        return replace(plan, steps=adjusted_steps)
    except TypeError:
        plan.steps = adjusted_steps
        return plan


def _save_agent_observation(runtime: SaberRuntime, session_id: str, observation: AgentObservation) -> None:
    """Persist one agent observation."""

    try:
        runtime.finding_store.save_observation(session_id, observation)
    except Exception:
        # Observations are useful, but should not make the whole mission fail
        # after orchestration completed.
        return




def split_plan_for_reporting(plan: ExecutionPlan) -> tuple[ExecutionPlan, ExecutionPlan | None]:
    """Split a plan into pre-report steps and report-only steps.

    This lets SABER parse evidence before the reporter agent runs.
    """

    reporter_steps = [step for step in plan.steps if step.agent_name == "reporter_agent"]
    if not reporter_steps:
        return plan, None

    pre_report_steps = [step for step in plan.steps if step.agent_name != "reporter_agent"]

    adjusted_reporter_steps = []
    for step in reporter_steps:
        try:
            adjusted_reporter_steps.append(replace(step, depends_on=[]))
        except TypeError:
            step.depends_on = []
            adjusted_reporter_steps.append(step)

    return _replace_plan_steps(plan, pre_report_steps), _replace_plan_steps(plan, adjusted_reporter_steps)


def _replace_plan_steps(plan: ExecutionPlan, steps: list) -> ExecutionPlan:
    """Return a copy of an ExecutionPlan with different steps."""

    try:
        return replace(plan, steps=steps)
    except TypeError:
        plan.steps = steps
        return plan


def _load_observations_for_reporter(
    runtime: SaberRuntime,
    session_id: str,
    fallback_observations: list[AgentObservation] | None = None,
) -> list[AgentObservation]:
    """Load stored observations and convert them back to AgentObservation objects."""

    observations: list[AgentObservation] = []

    try:
        rows = runtime.finding_store.list_observations(session_id)
    except Exception:
        rows = []

    for row in rows:
        observation = _row_to_agent_observation(row)
        if observation is not None:
            observations.append(observation)

    if observations:
        return observations

    return list(fallback_observations or [])


def _row_to_agent_observation(row: object) -> AgentObservation | None:
    """Convert a stored observation row/dict into an AgentObservation."""

    if not isinstance(row, dict):
        if hasattr(row, "to_dict"):
            try:
                row = row.to_dict()
            except Exception:
                return None
        elif hasattr(row, "model_dump"):
            try:
                row = row.model_dump(mode="json")
            except Exception:
                return None
        else:
            return None

    raw = row.get("observation") if isinstance(row.get("observation"), dict) else row

    summary = (
        raw.get("summary")
        or raw.get("description")
        or raw.get("title")
        or row.get("summary")
        or "Stored observation"
    )

    metadata = raw.get("metadata") or row.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"raw_metadata": metadata}

    try:
        return AgentObservation(
            summary=str(summary),
            success=bool(raw.get("success", True)),
            tool_name=raw.get("tool_name") or row.get("tool_name"),
            action=raw.get("action") or row.get("action"),
            metadata=metadata,
        )
    except Exception:
        return None


def _safe_count(loader) -> int:
    """Safely count list-returning storage calls."""

    try:
        return len(loader())
    except Exception:
        return 0

def _index_sandbox_evidence(runtime: SaberRuntime, session_id: str, mission_started_at: float = 0.0) -> list[str]:
    """Index sandbox EvidenceStore files into Storage EvidenceIndex.

    Sandbox evidence is saved by saber.core.evidence_store.EvidenceStore.
    The CLI/web UI reads from saber.storage.evidence_index.EvidenceIndex.
    This function bridges those two layers.
    """

    sandbox = getattr(runtime, "sandbox", None)
    evidence_store = getattr(sandbox, "evidence_store", None)
    records = getattr(evidence_store, "_records", {}) or {}

    indexed: list[str] = []

    for record in records.values():
        title = _record_attr(record, "title") or "Sandbox evidence"
        tool_name = _record_attr(record, "tool_name") or _record_attr(record, "tool") or None
        metadata = _record_metadata(record)

        candidate_paths = _record_candidate_paths(record)

        for candidate in candidate_paths:
            if not candidate.exists() or not candidate.is_file():
                continue

            try:
                if _evidence_path_already_indexed(runtime, session_id, candidate):
                    continue

                resolved_tool = tool_name or metadata.get("tool_name") or metadata.get("tool")
                resolved_action = metadata.get("tool_action") or metadata.get("action")
                evidence_id = runtime.evidence_index.add_evidence(
                    session_id=session_id,
                    step_id=metadata.get("step_id") or resolved_tool,
                    tool_name=resolved_tool,
                    action=resolved_action,
                    title=f"{title}: {candidate.name}",
                    path=candidate,
                    metadata={
                        "source": "sandbox_evidence_store",
                        "sandbox_record": _record_to_dict(record),
                        "indexed_from": str(candidate),
                    },
                )
                indexed.append(evidence_id)

                if resolved_tool:
                    runtime.result_processor.process_evidence_file(
                        session_id=session_id,
                        path=candidate,
                        tool_name=str(resolved_tool),
                        step_id=metadata.get("step_id") or str(resolved_tool),
                        action=resolved_action,
                        evidence_id=evidence_id,
                        metadata={
                            "source": "sandbox_evidence_store",
                            "indexed_from": str(candidate),
                        },
                    )
            except Exception:
                continue

    # Fallback: EvidenceStore may keep records without exposing file paths.
    # Index files created under the configured evidence dir during this mission.
    evidence_root = Path(runtime.config.evidence_dir)
    if evidence_root.exists():
        for candidate in sorted(evidence_root.rglob("*")):
            if not candidate.is_file():
                continue
            try:
                if candidate.stat().st_mtime < mission_started_at:
                    continue
            except OSError:
                continue

            already_indexed = False
            for existing in runtime.evidence_index.list_evidence(session_id):
                if str(existing.get("path")) == str(candidate):
                    already_indexed = True
                    break
            if already_indexed:
                continue

            try:
                tool_name, action = _guess_tool_action_from_path(candidate)
                evidence_id = runtime.evidence_index.add_evidence(
                    session_id=session_id,
                    step_id=tool_name if tool_name else None,
                    tool_name=tool_name,
                    action=action,
                    title=f"Sandbox evidence: {candidate.name}",
                    path=candidate,
                    metadata={
                        "source": "sandbox_evidence_scan",
                        "indexed_from": str(candidate),
                    },
                )
                indexed.append(evidence_id)

                if tool_name:
                    runtime.result_processor.process_evidence_file(
                        session_id=session_id,
                        path=candidate,
                        tool_name=tool_name,
                        step_id=tool_name,
                        action=action,
                        evidence_id=evidence_id,
                        metadata={
                            "source": "sandbox_evidence_scan",
                            "indexed_from": str(candidate),
                        },
                    )
            except Exception:
                continue

    return indexed


def _guess_tool_action_from_path(path: Path) -> tuple[str | None, str | None]:
    """Guess tool/action from EvidenceStore path layout."""

    parts = path.parts
    # Common layout: runs/evidence/recon/nmap/service_scan/file.txt
    for index, part in enumerate(parts):
        if part in {"nmap", "nuclei", "whatweb", "searchsploit", "amass", "subfinder", "dnsrecon", "nikto", "sqlmap"}:
            action = parts[index + 1] if index + 1 < len(parts) else None
            return part, action
    return None, None



def _evidence_path_already_indexed(runtime: SaberRuntime, session_id: str, path: Path) -> bool:
    """Return True if an evidence path has already been indexed for this session."""

    try:
        existing = runtime.evidence_index.list_evidence(session_id)
    except Exception:
        return False

    path_str = str(path)
    for item in existing:
        if str(item.get("path")) == path_str:
            return True
    return False

def _record_candidate_paths(record: object) -> list[Path]:
    """Extract likely evidence file paths from an EvidenceRecord."""

    paths: list[Path] = []

    direct_fields = (
        "path",
        "file_path",
        "filepath",
        "stdout_path",
        "stderr_path",
        "metadata_path",
        "output_path",
    )

    for field_name in direct_fields:
        value = _record_attr(record, field_name)
        if value:
            paths.append(Path(str(value)))

    files = _record_attr(record, "files")
    if isinstance(files, dict):
        for value in files.values():
            if value:
                paths.append(Path(str(value)))
    elif isinstance(files, list | tuple):
        for value in files:
            if value:
                paths.append(Path(str(value)))

    artifacts = _record_attr(record, "artifacts")
    if isinstance(artifacts, dict):
        for value in artifacts.values():
            if value:
                paths.append(Path(str(value)))
    elif isinstance(artifacts, list | tuple):
        for value in artifacts:
            if value:
                paths.append(Path(str(value)))

    metadata = _record_metadata(record)
    for key in ("path", "stdout_path", "stderr_path", "output_path"):
        value = metadata.get(key)
        if value:
            paths.append(Path(str(value)))

    # Fallback: inspect all string-ish values that look like files.
    record_dict = _record_to_dict(record)
    for value in record_dict.values():
        if isinstance(value, str) and ("/" in value or value.startswith("runs")):
            paths.append(Path(value))

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        resolved = path.expanduser()
        key = str(resolved)
        if key not in seen:
            seen.add(key)
            deduped.append(resolved)

    return deduped


def _record_metadata(record: object) -> dict:
    """Extract metadata from evidence record."""

    metadata = _record_attr(record, "metadata")
    if isinstance(metadata, dict):
        return dict(metadata)
    return {}


def _record_attr(record: object, name: str):
    """Read attribute or dict key."""

    if isinstance(record, dict):
        return record.get(name)
    return getattr(record, name, None)


def _record_to_dict(record: object) -> dict:
    """Convert record to dict if possible."""

    if isinstance(record, dict):
        return dict(record)

    if hasattr(record, "to_dict"):
        try:
            return record.to_dict()
        except Exception:
            return {}

    if hasattr(record, "model_dump"):
        try:
            return record.model_dump(mode="json")
        except Exception:
            return {}

    data = {}
    for key in dir(record):
        if key.startswith("_"):
            continue
        try:
            value = getattr(record, key)
        except Exception:
            continue
        if callable(value):
            continue
        if isinstance(value, (str, int, float, bool, type(None), dict, list, tuple)):
            data[key] = value
    return data

def _make_session(
    session_id: str,
    mission_name: str,
    target_value: str,
    profile: str,
    dry_run: bool,
) -> MissionSession:
    """Create MissionSession with tolerant constructor handling."""

    metadata = {
        "target": target_value,
        "profile": profile,
        "dry_run": dry_run,
    }

    attempts = (
        {
            "session_id": session_id,
            "mission_name": mission_name,
            "metadata": metadata,
        },
        {
            "session_id": session_id,
            "mission_name": mission_name,
        },
    )

    for kwargs in attempts:
        try:
            return MissionSession(**kwargs)
        except Exception:
            continue

    if hasattr(MissionSession, "model_construct"):
        return MissionSession.model_construct(
            session_id=session_id,
            mission_name=mission_name,
            metadata=metadata,
        )

    raise RuntimeError("Could not construct MissionSession.")


def _make_target(target_value: str) -> Target:
    """Create Target with tolerant constructor handling."""

    attempts = (
        {"type": TargetType.HOST, "value": target_value},
        {"target_type": TargetType.HOST, "value": target_value},
        {"kind": TargetType.HOST, "value": target_value},
        {"type": "host", "value": target_value},
        {"target_type": "host", "value": target_value},
        {"value": target_value},
    )

    for kwargs in attempts:
        try:
            return Target(**kwargs)
        except Exception:
            continue

    if hasattr(Target, "model_construct"):
        return Target.model_construct(
            type=TargetType.HOST,
            target_type=TargetType.HOST,
            value=target_value,
            metadata={},
        )

    raise RuntimeError("Could not construct Target.")


def _objective_for_profile(profile: str, target_value: str) -> str:
    """Return default objective for profile."""

    objectives = {
        "recon": f"Perform safe reconnaissance against {target_value}.",
        "web": f"Perform web-focused reconnaissance and passive/low-risk web assessment against {target_value}.",
        "network": f"Perform network-focused discovery and service analysis against {target_value}.",
        "ad": f"Perform Active Directory-oriented discovery and path analysis against {target_value}.",
        "full": f"Perform full scoped assessment against {target_value}, pausing for approval where required.",
    }
    return objectives[profile]


def _safe_decision_dict(decision: Any) -> dict[str, Any]:
    """Return JSON-compatible decision."""

    if decision is None:
        return {}

    if hasattr(decision, "to_dict"):
        return decision.to_dict()

    if hasattr(decision, "model_dump"):
        return decision.model_dump(mode="json")

    return {
        "action_type": str(getattr(decision, "action_type", "")),
        "objective": str(getattr(decision, "objective", "")),
        "message": str(getattr(decision, "message", "")),
        "metadata": getattr(decision, "metadata", {}),
    }


def _path(value: str) -> Any:
    """Return path string as accepted by SaberConfig."""

    return Path(value)
