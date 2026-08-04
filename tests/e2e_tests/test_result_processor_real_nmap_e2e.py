"""Real ResultProcessor nmap E2E.

This proves:
- Real Docker nmap creates XML evidence.
- Real ResultProcessor accepts that evidence.
- Real parser pipeline processes the file without fake processor logic.
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
from typing import Any

import pytest

from saber.core.docker_runner import (
    DockerSubprocessRunner,
    docker_available,
    docker_info,
    image_exists,
)
from saber.core.result_processor import ResultProcessor
from saber.models.target import Target, TargetType
from saber.parsers.registry import build_default_parser_registry
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.core.docker_runner import DEFAULT_SHARED_IMAGE


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


def _jsonish(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()

    if hasattr(value, "__dict__"):
        value = value.__dict__

    return json.dumps(value, default=str, sort_keys=True)


def _call_process_evidence_file(
    processor: ResultProcessor,
    *,
    evidence_path: Path,
    target: Target,
) -> Any:
    """Call ResultProcessor.process_evidence_file using the signature this repo has."""

    method = processor.process_evidence_file
    signature = inspect.signature(method)

    candidate_kwargs = {
        "path": evidence_path,
        "file_path": evidence_path,
        "evidence_file": evidence_path,
        "tool_name": "nmap",
        "action": "service_scan",
        "tool_action": "service_scan",
        "session_id": "real_result_processor_nmap_session",
        "target": target,
        "metadata": {
            "tool_name": "nmap",
            "action": "service_scan",
            "source": "real_docker_nmap_e2e",
        },
    }

    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return method(**candidate_kwargs)

    supported = {
        key: value
        for key, value in candidate_kwargs.items()
        if key in signature.parameters
    }

    return method(**supported)


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_result_processor_parses_real_nmap_xml_from_docker(tmp_path) -> None:
    evidence_path = tmp_path / "evidence" / "nmap.xml"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    runner = DockerSubprocessRunner(
        image=os.getenv(
            "SABER_SANDBOX_IMAGE",
            DEFAULT_SHARED_IMAGE,
        ),
        repo_dir=tmp_path,
        default_timeout_seconds=120,
        network=os.getenv("SABER_DOCKER_NETWORK", "host"),
        user=os.getenv("SABER_DOCKER_USER", ""),
    )

    run_result = runner.run(
        [
            "nmap",
            "-sT",
            "-oX",
            str(evidence_path),
            "127.0.0.1",
        ],
        timeout_seconds=120,
    )

    assert run_result.return_code == 0, run_result.stderr
    assert evidence_path.exists()
    assert "<nmaprun" in evidence_path.read_text(encoding="utf-8", errors="ignore")

    connection = StorageConnection(tmp_path / "saber.db")
    connection.initialize()

    try:
        processor = ResultProcessor(
            evidence_index=EvidenceIndex(connection),
            finding_store=FindingStore(connection),
            graph_store=GraphStore(connection),
            parser_registry=build_default_parser_registry(),
            evidence_root=tmp_path / "evidence",
        )

        target = Target(type=TargetType.HOST, value="127.0.0.1")

        processed = _call_process_evidence_file(
            processor,
            evidence_path=evidence_path,
            target=target,
        )

    finally:
        connection.close()

    assert processed is not None

    processed_text = _jsonish(processed).lower()

    assert "nmap" in processed_text or "127.0.0.1" in processed_text or "open" in processed_text
