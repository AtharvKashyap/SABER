"""Fake mission E2E test.

This proves the mission loop can:
step -> evidence -> result processor -> artifact export
without depending on real tools, Docker, or LLM calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.mission_orchestrator import MissionOrchestrator, MissionRunStatus
from saber.tools.registry import ToolRegistry


@dataclass
class FakeObservation:
    """Fake agent observation compatible with MissionRunResult serialization."""

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
class FakeStep:
    """Fake execution step."""

    step_id: str = "fake-step-1"

    def mark_running(self):
        return self


class FakePlan:
    """Fake execution plan with one runnable step."""

    def __init__(self) -> None:
        self.completed = False
        self.failed = False
        self.blocking_approval = False
        self.step = FakeStep()

    def has_blocking_approval(self) -> bool:
        return self.blocking_approval

    def has_failed_step(self) -> bool:
        return self.failed

    def runnable_steps(self) -> list[FakeStep]:
        return [] if self.completed else [self.step]

    def update_step(self, step):
        return self

    def is_complete(self) -> bool:
        return self.completed

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_name": "Fake Mission",
            "complete": self.completed,
            "failed": self.failed,
            "blocking_approval": self.blocking_approval,
        }


class FakeRecord:
    """Fake StepRunRecord compatible with MissionOrchestrator."""

    def __init__(self, evidence_path: Path) -> None:
        self.requires_approval = False
        self.new_observations = [
            FakeObservation(
                summary="Fake nmap evidence created.",
                tool_name="nmap",
                action="service_scan",
                success=True,
                metadata={"evidence_path": str(evidence_path)},
            )
        ]
        self.evidence_path = str(evidence_path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": "fake-step-1",
            "agent_name": "recon_agent",
            "tool_name": "nmap",
            "action": "service_scan",
            "success": True,
            "requires_approval": False,
            "evidence_path": self.evidence_path,
        }


class FakeStepRunner:
    """Fake step runner that emits one evidence file."""

    def __init__(self, evidence_path: Path) -> None:
        self.evidence_path = evidence_path
        self.calls = 0

    def run_step(self, **kwargs) -> FakeRecord:
        self.calls += 1
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_path.write_text(
            """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
            encoding="utf-8",
        )
        return FakeRecord(self.evidence_path)


class FakeChainRunner:
    """Fake chain runner that completes after one record."""

    def process_step_record(self, plan: FakePlan, record: FakeRecord) -> FakePlan:
        plan.completed = True
        return plan

    def should_stop(self, plan: FakePlan) -> bool:
        return plan.is_complete()


class FakeResultProcessor:
    """Fake result processor that records evidence processing calls."""

    def __init__(self) -> None:
        self.processed: list[dict[str, Any]] = []

    def process_evidence_file(
        self,
        path: Path,
        tool_name: str | None = None,
        action: str | None = None,
        session_id: str | None = None,
        target: Target | None = None,
    ) -> dict[str, Any]:
        assert path.exists()
        payload = {
            "path": str(path),
            "tool_name": tool_name,
            "action": action,
            "session_id": session_id,
            "target": target.value if target else None,
            "finding_count": 1,
        }
        self.processed.append(payload)
        return payload


class NoopRunner:
    """No-op sandbox runner."""

    def run(self, command, **kwargs):
        raise AssertionError("Fake E2E should not execute real commands.")


def test_fake_mission_e2e_processes_evidence_and_exports_result(tmp_path) -> None:
    session = MissionSession(session_id="fake_e2e_session", mission_name="Fake E2E Mission")
    target = Target(type=TargetType.HOST, value="127.0.0.1")
    evidence_path = tmp_path / "runs" / "evidence" / "fake_e2e_session" / "nmap.xml"

    result_processor = FakeResultProcessor()
    step_runner = FakeStepRunner(evidence_path)
    chain_runner = FakeChainRunner()

    orchestrator = MissionOrchestrator(
        agents={"recon_agent": object()},
        tool_registry=ToolRegistry(),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), NoopRunner()),
        step_runner=step_runner,
        chain_runner=chain_runner,
        result_processor=result_processor,
        reports_dir=tmp_path / "reports",
        max_steps=5,
    )

    result = orchestrator.run_until_pause_or_complete(
        plan=FakePlan(),
        session=session,
        target=target,
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "fake_e2e"},
    )

    assert result.status == MissionRunStatus.COMPLETED
    assert step_runner.calls == 1
    assert len(result_processor.processed) == 1

    processed = result_processor.processed[0]
    assert processed["tool_name"] == "nmap"
    assert processed["action"] == "service_scan"
    assert processed["session_id"] == "fake_e2e_session"
    assert processed["target"] == "127.0.0.1"

    mission_result_path = tmp_path / "reports" / "fake_e2e_session" / "mission_result.json"
    assert mission_result_path.exists()

    artifact_kinds = [artifact.kind for artifact in result.artifacts]
    assert "processed_evidence" in artifact_kinds
    assert "mission_result_json" in artifact_kinds
