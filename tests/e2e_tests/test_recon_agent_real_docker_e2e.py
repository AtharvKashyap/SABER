"""Real ReconAgent + real Docker tool execution E2E.

This proves:
- real ReconAgent decides to run nmap/service_scan
- real StepRunner executes that decision
- real ToolRegistry loads NmapWrapper
- real NmapWrapper runs through DockerSubprocessRunner
- real evidence is created by Sandbox/EvidenceStore
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from saber.agents.recon_agent import ReconAgent
from saber.core.docker_runner import DockerSubprocessRunner, docker_available, docker_info, image_exists
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunner
from saber.tools.registry import ToolRegistry, default_tool_entries


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


def _all_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return [path for path in root.rglob("*") if path.is_file()]


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_real_recon_agent_runs_real_nmap_through_step_runner(tmp_path) -> None:
    evidence_root = tmp_path / "evidence"

    runner = DockerSubprocessRunner(
        image=os.getenv(
            "SABER_SANDBOX_IMAGE",
            "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release",
        ),
        repo_dir=tmp_path,
        default_timeout_seconds=180,
        network=os.getenv("SABER_DOCKER_NETWORK", "host"),
        user=os.getenv("SABER_DOCKER_USER", ""),
    )

    sandbox = Sandbox(EvidenceStore(evidence_root), runner)
    registry = ToolRegistry(default_tool_entries())
    recon_agent = ReconAgent()

    step_runner = StepRunner(
        agents={"recon_agent": recon_agent},
        tool_registry=registry,
        sandbox=sandbox,
    )

    session = MissionSession(
        session_id="real_recon_agent_session",
        mission_name="Real ReconAgent Docker E2E",
    )
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    step = ExecutionStep(
        step_id="real_recon_agent_nmap",
        agent_name="recon_agent",
        objective="Run baseline service discovery.",
        phase=AssessmentPhase.RECON,
        target=target,
    )

    record = step_runner.run_step(
        step=step,
        session=session,
        target=target,
        observations=[],
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "real_recon_agent_docker"},
    )

    assert record.step_id == "real_recon_agent_nmap"
    assert record.agent_name == "recon_agent"
    assert record.status == ExecutionStepStatus.COMPLETED
    assert record.requires_approval is False

    assert record.agent_result.decision.tool_call is not None
    assert record.agent_result.decision.tool_call.tool_name == "nmap"
    assert record.agent_result.decision.tool_call.action == "service_scan"

    assert record.new_observations, "Expected ReconAgent/StepRunner to emit tool observations."

    nmap_observations = [
        obs for obs in record.new_observations
        if obs.tool_name == "nmap" and obs.action == "service_scan"
    ]
    assert nmap_observations, "Expected an nmap/service_scan observation."

    assert any(obs.success for obs in nmap_observations), [
        {
            "summary": obs.summary,
            "metadata": obs.metadata,
        }
        for obs in nmap_observations
    ]

    files = _all_files(evidence_root)
    assert files, "Expected Sandbox/EvidenceStore to write real evidence files."

    combined = "\\n".join(
        path.read_text(encoding="utf-8", errors="ignore")[:5000]
        for path in files
    )

    assert "Nmap" in combined or "<nmaprun" in combined or "PORT" in combined
