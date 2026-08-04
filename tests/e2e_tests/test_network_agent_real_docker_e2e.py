"""Real NetworkAgent + real Docker execution E2E.

This proves:
- real NetworkAgent chooses a safe network enumeration action
- real StepRunner executes the NetworkAgent decision
- real ToolRegistry loads Enum4LinuxWrapper
- real enum4linux runs through DockerSubprocessRunner
- evidence is written by Sandbox/EvidenceStore

This does not require a working SMB service. The goal of number 8 is proving
the real network-agent execution path and evidence creation.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from saber.agents.base_agent import AgentObservation
from saber.agents.network_agent import NetworkAgent
from saber.core.docker_runner import (
    DEFAULT_SHARED_IMAGE,
    DockerSubprocessRunner,
    docker_available,
    docker_info,
    image_exists,
)
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunner
from saber.tools.registry import ToolRegistry, default_tool_entries
from tests.support.docker_host import sandbox_host_address

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
def test_real_network_agent_runs_real_enum4linux_through_step_runner(tmp_path) -> None:
    docker_network = os.getenv("SABER_DOCKER_NETWORK", "host")
    evidence_root = tmp_path / "evidence"

    runner = DockerSubprocessRunner(
        image=os.getenv(
            "SABER_SANDBOX_IMAGE",
            DEFAULT_SHARED_IMAGE,
        ),
        repo_dir=tmp_path,
        default_timeout_seconds=180,
        network=docker_network,
        user=os.getenv("SABER_DOCKER_USER", ""),
    )

    sandbox = Sandbox(EvidenceStore(evidence_root), runner)
    registry = ToolRegistry(default_tool_entries())
    network_agent = NetworkAgent()

    step_runner = StepRunner(
        agents={"network_agent": network_agent},
        tool_registry=registry,
        sandbox=sandbox,
    )

    session = MissionSession(
        session_id="real_network_agent_session",
        mission_name="Real NetworkAgent Docker E2E",
    )

    # The route from the container to this machine is platform-specific; see
    # tests/support/docker_host.py. enum4linux still produces evidence even if SMB
    # is closed, so what matters is that the address resolves at all.
    host_address = sandbox_host_address(docker_network)
    if host_address is None:
        pytest.skip(f"no route from the sandbox to this host on network {docker_network!r}")
    target = Target(
        type=TargetType.IP if host_address[0].isdigit() else TargetType.HOST,
        value=host_address,
    )

    step = ExecutionStep(
        step_id="real_network_agent_enum4linux",
        agent_name="network_agent",
        objective="Enumerate observed SMB network service.",
        phase=AssessmentPhase.NETWORK,
        target=target,
    )

    observations = [
        AgentObservation(
            summary="Open SMB service discovered on port 445.",
            tool_name="nmap",
            action="service_scan",
            success=True,
            metadata={
                "finding_type": "open_service",
                "service": "smb",
                "port": 445,
            },
        )
    ]

    record = step_runner.run_step(
        step=step,
        session=session,
        target=target,
        observations=observations,
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "real_network_agent_docker"},
    )

    assert record.step_id == "real_network_agent_enum4linux"
    assert record.agent_name == "network_agent"

    assert record.agent_result.decision.tool_call is not None
    assert record.agent_result.decision.tool_call.tool_name == "enum4linux"
    assert record.agent_result.decision.tool_call.action == "shares"

    assert record.new_observations, "Expected NetworkAgent/StepRunner to emit tool observations."

    enum_observations = [
        obs for obs in record.new_observations
        if obs.tool_name == "enum4linux" and obs.action == "shares"
    ]
    assert enum_observations, "Expected an enum4linux/shares observation."

    files = _all_files(evidence_root)
    assert files, "Expected Sandbox/EvidenceStore to write real enum4linux evidence."

    combined = "\\n".join(
        path.read_text(encoding="utf-8", errors="ignore")[:5000]
        for path in files
    )

    assert "enum4linux" in combined.lower() or "smb" in combined.lower() or "shares" in combined.lower()

    # The tool may return non-zero if no SMB service is present. That is okay
    # for this slice. The important part is real wrapper execution + evidence.
    assert record.status in {
        ExecutionStepStatus.COMPLETED,
        ExecutionStepStatus.FAILED,
    }
