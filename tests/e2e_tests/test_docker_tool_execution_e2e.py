"""Real Docker tool execution E2E.

This proves:
- DockerSubprocessRunner can execute a real tool inside the SABER sandbox image.
- A real tool can write evidence back to the host filesystem.
"""

from __future__ import annotations

import os

import pytest

from saber.core.docker_runner import (
    DockerSubprocessRunner,
    docker_available,
    docker_info,
    image_exists,
)


pytestmark = pytest.mark.e2e


def _docker_ready() -> bool:
    return docker_available() and docker_info().ok and image_exists()


@pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_DOCKER_E2E=1 to run real Docker E2E tests.",
)
@pytest.mark.skipif(
    not _docker_ready(),
    reason="Docker daemon or SABER sandbox image is not available.",
)
def test_docker_runner_executes_real_nmap_and_writes_evidence(tmp_path) -> None:
    evidence_path = tmp_path / "nmap.xml"

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

    result = runner.run(
        [
            "nmap",
            "-sT",
            "-oX",
            str(evidence_path),
            "127.0.0.1",
        ],
        timeout_seconds=120,
    )

    assert result.return_code == 0, result.stderr
    assert evidence_path.exists()
    assert "<nmaprun" in evidence_path.read_text(encoding="utf-8", errors="ignore")
    assert result.metadata["runner"] == "docker_subprocess"
