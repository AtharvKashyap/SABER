"""Docker-gated lab missions. Requires `make lab-up` first.

Gated by SABER_RUN_DOCKER_E2E; skips cleanly when the lab is not reachable.
"""

import os
import socket
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0") not in {"1", "true", "True"},
    reason="Docker E2E gated behind SABER_RUN_DOCKER_E2E=1",
)

_LAB_NETWORK = os.getenv("SABER_DOCKER_NETWORK", "saber-lab")


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _reachable_in_lab_network(host: str, port: int) -> bool:
    """Probe from INSIDE the lab network, the way the sandbox actually connects.

    The lab compose publishes no host ports: dvwa is only resolvable and reachable on
    the `saber-lab` docker network. A host-side socket probe therefore ALWAYS failed,
    so this test could only ever skip — it was gated on a condition that could not
    become true, while the mission it guards would have worked fine.
    """

    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, test-only Docker probe
            [
                "docker",
                "run",
                "--rm",
                "--network",
                _LAB_NETWORK,
                "--entrypoint",
                "sh",
                os.getenv("SABER_SANDBOX_IMAGE", "saber-sandbox:f7"),
                "-lc",
                f"nc -z -w 3 {host} {port}",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _lab_target_available(host: str, port: int) -> bool:
    """True when the target is reachable either from the host or inside the network."""

    return _reachable(host, port) or _reachable_in_lab_network(host, port)


def test_web_mission_against_dvwa(tmp_path):
    from saber.ui.cli.run_command import run_cli_mission

    if not _lab_target_available("dvwa", 80):
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

    # "It terminated" is not the interesting claim — "it LEARNED something from a real
    # target" is. This is the only test in the repo that proves the whole chain
    # (decide -> gate -> execute in Docker -> parse -> merge -> snapshot) works against
    # a live service rather than a fixture, so it asserts the state actually grew.
    from saber.storage.connection import StorageConnection
    from saber.storage.mission_state_store import MissionStateStore

    connection = StorageConnection(str(tmp_path / "saber.db"))
    state = MissionStateStore(connection).load(result["session_id"])
    assert state is not None, "the mission left no MissionState snapshot"

    learned = len(state.hosts) + len(state.services) + len(state.technologies)
    assert learned >= 1, (
        "mission ran against a live target but MissionState stayed empty "
        f"(hosts={len(state.hosts)} services={len(state.services)} "
        f"technologies={len(state.technologies)}) — tools executed but nothing was "
        "normalized back into state, which is the exact defect Workstream F fixed"
    )

    # A real run must leave evidence behind, not just state.
    assert state.attempted_actions, "no action was recorded on the state"
