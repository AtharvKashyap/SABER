"""Real StepRunner + Docker execution E2E.

This proves:
- real ExecutionStep enters real StepRunner
- StepRunner builds AgentContext correctly
- agent.run(context) can execute real Docker tools through context.sandbox
- real nmap XML evidence is written to host filesystem

This does not yet test ReconAgent. That is number 5.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from saber.agents.base_agent import AgentRunStatus
from saber.core.docker_runner import DockerSubprocessRunner, docker_available, docker_info, image_exists
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunner
from saber.tools.registry import ToolRegistry


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


def _recon_phase() -> AssessmentPhase:
    for phase in AssessmentPhase:
        if phase.value in {"recon", "reconnaissance"}:
            return phase
    raise AssertionError(f"No recon phase found in AssessmentPhase: {[p.value for p in AssessmentPhase]}")


class DockerNmapAgent:
    """Tiny agent used only to prove StepRunner can execute real Docker tools."""

    def __init__(self, evidence_path: Path) -> None:
        self.config = SimpleNamespace(
            name="docker_nmap_agent",
            phase=_recon_phase(),
        )
        self.evidence_path = evidence_path
        self.calls = 0

    def run(self, context) -> Any:
        self.calls += 1
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)

        result = context.sandbox.runner.run(
            [
                "nmap",
                "-sT",
                "-oX",
                str(self.evidence_path),
                context.target.value,
            ],
            timeout_seconds=120,
        )

        observation = SimpleNamespace(
            summary="StepRunner agent executed real Docker nmap.",
            tool_name="nmap",
            action="service_scan",
            success=result.return_code == 0,
            metadata={
                "evidence_path": str(self.evidence_path),
                "return_code": result.return_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )

        decision = SimpleNamespace(
            action_type=SimpleNamespace(value="run_tool"),
            handoff_agent=None,
        )

        return SimpleNamespace(
            agent_name=self.config.name,
            status=AgentRunStatus.COMPLETED if result.return_code == 0 else AgentRunStatus.FAILED,
            decision=decision,
            observations=[observation],
            metadata={
                "evidence_path": str(self.evidence_path),
                "return_code": result.return_code,
            },
        )


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_real_step_runner_executes_real_docker_nmap(tmp_path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_path = evidence_root / "step_runner_session" / "nmap.xml"

    runner = DockerSubprocessRunner(
        image=os.getenv(
            "SABER_SANDBOX_IMAGE",
            "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release",
        ),
        repo_dir=tmp_path,
        default_timeout_seconds=120,
        network=os.getenv("SABER_DOCKER_NETWORK", "host"),
        user=os.getenv("SABER_DOCKER_USER", ""),
    )

    sandbox = Sandbox(EvidenceStore(evidence_root), runner)
    agent = DockerNmapAgent(evidence_path=evidence_path)

    step_runner = StepRunner(
        agents={"docker_nmap_agent": agent},
        tool_registry=ToolRegistry(),
        sandbox=sandbox,
    )

    session = MissionSession(
        session_id="step_runner_session",
        mission_name="StepRunner Docker E2E",
    )
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    step = ExecutionStep(
        step_id="step_runner_real_nmap",
        agent_name="docker_nmap_agent",
        objective="Run a Docker-safe nmap TCP connect scan.",
        phase=_recon_phase(),
        target=target,
    )

    record = step_runner.run_step(
        step=step,
        session=session,
        target=target,
        observations=[],
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "step_runner_docker_execution"},
    )

    assert agent.calls == 1
    assert record.step_id == "step_runner_real_nmap"
    assert record.agent_name == "docker_nmap_agent"
    assert record.status == ExecutionStepStatus.COMPLETED
    assert record.requires_approval is False

    assert len(record.new_observations) == 1
    observation = record.new_observations[0]
    assert observation.tool_name == "nmap"
    assert observation.action == "service_scan"
    assert observation.success is True

    assert evidence_path.exists()
    assert "<nmaprun" in evidence_path.read_text(encoding="utf-8", errors="ignore")
