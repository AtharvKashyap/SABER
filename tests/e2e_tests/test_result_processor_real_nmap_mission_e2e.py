"""Real ResultProcessor E2E with real Docker nmap evidence.

This proves:
- real Docker nmap creates XML evidence
- MissionOrchestrator sees the evidence file
- real ResultProcessor is called during the mission
- nmap XML processing does not error
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from saber.core.docker_runner import DockerSubprocessRunner, docker_available, docker_info, image_exists
from saber.core.evidence_store import EvidenceStore
from saber.core.result_processor import ResultProcessor
from saber.core.sandbox import Sandbox
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.mission_orchestrator import MissionOrchestrator, MissionRunStatus
from saber.parsers.registry import build_default_parser_registry
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.tools.registry import ToolRegistry


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


@dataclass
class RealObservation:
    """Observation pointing to real evidence."""

    summary: str
    tool_name: str | None = None
    action: str | None = None
    success: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "tool_name": self.tool_name,
            "action": self.action,
            "success": self.success,
            "metadata": self.metadata,
        }


@dataclass
class OneStep:
    """Minimal fake step."""

    step_id: str = "real-nmap-parse-step"

    def mark_running(self):
        return self


class OneStepPlan:
    """Minimal one-step plan."""

    def __init__(self) -> None:
        self.completed = False
        self.failed = False
        self.blocking_approval = False
        self.step = OneStep()

    def has_blocking_approval(self) -> bool:
        return self.blocking_approval

    def has_failed_step(self) -> bool:
        return self.failed

    def runnable_steps(self) -> list[OneStep]:
        return [] if self.completed else [self.step]

    def update_step(self, step):
        return self

    def is_complete(self) -> bool:
        return self.completed

    def to_dict(self) -> dict[str, Any]:
        return {"complete": self.completed, "failed": self.failed}


class RealNmapRecord:
    """Fake StepRunRecord wrapper around a real nmap run."""

    def __init__(self, evidence_path: Path, return_code: int, stdout: str, stderr: str) -> None:
        self.requires_approval = False
        self.evidence_path = str(evidence_path)
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        self.new_observations = [
            RealObservation(
                summary="Real nmap XML evidence created.",
                tool_name="nmap",
                action="service_scan",
                success=return_code == 0,
                metadata={
                    "evidence_path": str(evidence_path),
                    "return_code": return_code,
                    "stdout": stdout,
                    "stderr": stderr,
                },
            )
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": "real-nmap-parse-step",
            "agent_name": "recon_agent",
            "tool_name": "nmap",
            "action": "service_scan",
            "success": self.return_code == 0,
            "requires_approval": False,
            "evidence_path": self.evidence_path,
            "return_code": self.return_code,
        }


class RealNmapStepRunner:
    """Runs real Docker nmap and writes XML evidence."""

    def __init__(self, sandbox: Sandbox, evidence_path: Path) -> None:
        self.sandbox = sandbox
        self.evidence_path = evidence_path
        self.calls = 0

    def run_step(self, **kwargs) -> RealNmapRecord:
        self.calls += 1
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)

        result = self.sandbox.runner.run(
            [
                "nmap",
                "-sT",
                "-oX",
                str(self.evidence_path),
                "127.0.0.1",
            ],
            timeout_seconds=120,
        )

        return RealNmapRecord(
            evidence_path=self.evidence_path,
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class CompleteAfterOneRecord:
    """Complete plan after one successful record."""

    def process_step_record(self, plan: OneStepPlan, record: RealNmapRecord) -> OneStepPlan:
        if record.return_code == 0:
            plan.completed = True
        else:
            plan.failed = True
        return plan

    def should_stop(self, plan: OneStepPlan) -> bool:
        return plan.is_complete() or plan.has_failed_step()


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_result_processor_parses_real_nmap_evidence_during_mission(tmp_path) -> None:
    db_path = tmp_path / "saber.db"
    evidence_root = tmp_path / "evidence"
    reports_dir = tmp_path / "reports"
    evidence_path = evidence_root / "real_nmap_parse_session" / "nmap.xml"

    connection = StorageConnection(db_path)
    connection.initialize()

    result_processor = ResultProcessor(
        evidence_index=EvidenceIndex(connection),
        finding_store=FindingStore(connection),
        graph_store=GraphStore(connection),
        parser_registry=build_default_parser_registry(),
        evidence_root=evidence_root,
    )

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

    step_runner = RealNmapStepRunner(sandbox=sandbox, evidence_path=evidence_path)

    orchestrator = MissionOrchestrator(
        agents={"recon_agent": object()},
        tool_registry=ToolRegistry(),
        sandbox=sandbox,
        step_runner=step_runner,
        chain_runner=CompleteAfterOneRecord(),
        result_processor=result_processor,
        reports_dir=reports_dir,
        max_steps=3,
    )

    session = MissionSession(
        session_id="real_nmap_parse_session",
        mission_name="Real Nmap Parse Mission",
    )
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    result = orchestrator.run_until_pause_or_complete(
        plan=OneStepPlan(),
        session=session,
        target=target,
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "result_processor_real_nmap"},
    )

    connection.close()

    assert result.status == MissionRunStatus.COMPLETED
    assert step_runner.calls == 1
    assert evidence_path.exists()
    assert "<nmaprun" in evidence_path.read_text(encoding="utf-8", errors="ignore")

    artifact_kinds = [artifact.kind for artifact in result.artifacts]
    assert "processed_evidence" in artifact_kinds
    assert "evidence_processing_error" not in artifact_kinds
    assert "mission_result_json" in artifact_kinds

    mission_result_path = reports_dir / "real_nmap_parse_session" / "mission_result.json"
    assert mission_result_path.exists()
