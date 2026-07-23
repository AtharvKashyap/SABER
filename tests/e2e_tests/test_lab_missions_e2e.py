"""Docker-gated lab missions. Requires `make lab-up` first.

Gated by SABER_RUN_DOCKER_E2E; skips cleanly when the lab is not reachable.
"""

import os
import socket

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0") not in {"1", "true", "True"},
    reason="Docker E2E gated behind SABER_RUN_DOCKER_E2E=1",
)


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def test_web_mission_against_dvwa(tmp_path):
    from saber.ui.cli.run_command import run_cli_mission

    if not _reachable("dvwa", 80) and not _reachable("127.0.0.1", 80):
        pytest.skip("DVWA not reachable; run `make lab-up` and set SABER_DOCKER_NETWORK=saber-lab")

    scope = tmp_path / "scope.yaml"
    scope.write_text("mission_name: Lab\ntargets:\n  - dvwa\n")
    result = run_cli_mission(
        target_value="dvwa",
        profile="web",
        agent_mode="deterministic",
        strategy="web",
        scope_path=str(scope),
        db_path=str(tmp_path / "saber.db"),
        evidence_dir=str(tmp_path / "evidence"),
        reports_dir=str(tmp_path / "reports"),
        max_steps=6,
    )
    assert result["status"] in {"completed", "stopped"}
    assert result["steps"] >= 1
