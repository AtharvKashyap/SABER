"""Real mission storage E2E.

This proves:
- real Docker nmap runs
- real nmap XML is processed
- ResultProcessor stores parsed findings/evidence in SQLite
"""

from __future__ import annotations

import os
import sqlite3

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

from tests.e2e_tests.test_result_processor_real_nmap_mission_e2e import (
    CompleteAfterOneRecord,
    OneStepPlan,
    RealNmapStepRunner,
)


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


def _count_rows_in_matching_tables(db_path, name_fragment: str) -> int:
    """Count rows across SQLite tables whose names contain name_fragment."""

    connection = sqlite3.connect(db_path)

    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            if name_fragment.lower() in row[0].lower()
        ]

        total = 0
        for table in tables:
            total += int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])

        return total

    finally:
        connection.close()


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_real_mission_stores_findings_from_real_nmap(tmp_path) -> None:
    db_path = tmp_path / "saber.db"
    evidence_root = tmp_path / "evidence"
    reports_dir = tmp_path / "reports"
    evidence_path = evidence_root / "real_storage_session" / "nmap.xml"

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
        session_id="real_storage_session",
        mission_name="Real Storage Mission",
    )
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    result = orchestrator.run_until_pause_or_complete(
        plan=OneStepPlan(),
        session=session,
        target=target,
        constraints={"agent_mode": "deterministic"},
        metadata={"test": "real_storage"},
    )

    connection.close()

    assert result.status == MissionRunStatus.COMPLETED
    assert evidence_path.exists()

    finding_rows = _count_rows_in_matching_tables(db_path, "finding")
    evidence_rows = _count_rows_in_matching_tables(db_path, "evidence")

    assert finding_rows > 0, "Expected ResultProcessor to store at least one finding."
    assert evidence_rows > 0, "Expected ResultProcessor to store evidence metadata."

    mission_result_path = reports_dir / "real_storage_session" / "mission_result.json"
    assert mission_result_path.exists()
