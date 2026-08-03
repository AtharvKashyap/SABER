"""Real WebAgent + real WhatWeb Docker execution E2E.

This proves:
- real WebAgent chooses whatweb/fingerprint
- real StepRunner executes the WebAgent decision
- real ToolRegistry loads WhatWebWrapper
- real WhatWeb runs through DockerSubprocessRunner
- evidence is written by Sandbox/EvidenceStore
"""

from __future__ import annotations

import functools
import http.server
import os
import socket
import socketserver
import threading
from pathlib import Path

import pytest

from saber.agents.base_agent import AgentObservation
from saber.agents.web_agent import WebAgent
from saber.core.docker_runner import DockerSubprocessRunner, docker_available, docker_info, image_exists
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunner
from saber.tools.registry import ToolRegistry, default_tool_entries
from saber.core.docker_runner import DEFAULT_SHARED_IMAGE


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "SABERTestHTTP/1.0"

    def log_message(self, format, *args):
        return


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def _start_test_http_server(root: Path) -> tuple[ThreadedTCPServer, threading.Thread, int]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(
        "<html><head><title>SABER WebAgent E2E</title></head>"
        "<body><h1>SABER WhatWeb Test</h1></body></html>",
        encoding="utf-8",
    )

    port = _free_port()
    handler = functools.partial(QuietHandler, directory=str(root))
    server = ThreadedTCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


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
def test_real_web_agent_runs_real_whatweb_through_step_runner(tmp_path) -> None:
    web_root = tmp_path / "webroot"
    server, thread, port = _start_test_http_server(web_root)

    try:
        evidence_root = tmp_path / "evidence"

        runner = DockerSubprocessRunner(
            image=os.getenv(
                "SABER_SANDBOX_IMAGE",
                DEFAULT_SHARED_IMAGE,
            ),
            repo_dir=tmp_path,
            default_timeout_seconds=180,
            network=os.getenv("SABER_DOCKER_NETWORK", "host"),
            user=os.getenv("SABER_DOCKER_USER", ""),
        )

        sandbox = Sandbox(EvidenceStore(evidence_root), runner)
        registry = ToolRegistry(default_tool_entries())
        web_agent = WebAgent()

        step_runner = StepRunner(
            agents={"web_agent": web_agent},
            tool_registry=registry,
            sandbox=sandbox,
        )

        # Docker Desktop on macOS reaches the host through host.docker.internal.
        target_url = f"http://host.docker.internal:{port}"

        session = MissionSession(
            session_id="real_web_agent_session",
            mission_name="Real WebAgent Docker E2E",
        )
        target = Target(type=TargetType.URL, value=target_url)

        step = ExecutionStep(
            step_id="real_web_agent_whatweb",
            agent_name="web_agent",
            objective="Fingerprint discovered web service.",
            phase=AssessmentPhase.RECON,
            target=target,
        )

        # Simulate ChainAgent having routed a discovered HTTP service to WebAgent.
        observations = [
            AgentObservation(
                summary=f"Open web service discovered at {target_url}.",
                tool_name="nmap",
                action="service_scan",
                success=True,
                metadata={
                    "finding_type": "open_service",
                    "service": "http",
                    "port": port,
                    "url": target_url,
                },
            )
        ]

        record = step_runner.run_step(
            step=step,
            session=session,
            target=target,
            observations=observations,
            constraints={"agent_mode": "deterministic"},
            metadata={"test": "real_web_agent_docker"},
        )

        assert record.step_id == "real_web_agent_whatweb"
        assert record.agent_name == "web_agent"
        assert record.status == ExecutionStepStatus.COMPLETED
        assert record.requires_approval is False

        assert record.agent_result.decision.tool_call is not None
        assert record.agent_result.decision.tool_call.tool_name == "whatweb"
        assert record.agent_result.decision.tool_call.action == "fingerprint"

        assert record.new_observations, "Expected WebAgent/StepRunner to emit tool observations."

        whatweb_observations = [
            obs for obs in record.new_observations
            if obs.tool_name == "whatweb" and obs.action == "fingerprint"
        ]
        assert whatweb_observations, "Expected a whatweb/fingerprint observation."

        assert any(obs.success for obs in whatweb_observations), [
            {
                "summary": obs.summary,
                "metadata": obs.metadata,
            }
            for obs in whatweb_observations
        ]

        files = _all_files(evidence_root)
        assert files, "Expected Sandbox/EvidenceStore to write real WhatWeb evidence."

        combined = "\\n".join(
            path.read_text(encoding="utf-8", errors="ignore")[:5000]
            for path in files
        )

        assert "WhatWeb" in combined or "SABER WebAgent E2E" in combined or "Title" in combined

    finally:
        server.shutdown()
        server.server_close()
