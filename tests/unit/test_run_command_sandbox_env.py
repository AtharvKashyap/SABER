"""run_cli_mission must honor env-driven sandbox config.

Regression: run_cli_mission built SaberConfig by hand and never set
docker_network/sandbox_image, so they defaulted to "host" and SABER_DOCKER_NETWORK
in .env was ignored — tool containers never joined the lab network and could not
resolve lab targets (nmap: "Failed to resolve dvwa").
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from saber.ui.cli import run_command


def _run_capture_config(**overrides):
    with patch.object(run_command, "load_env_file"):  # isolate from real .env
        with patch.object(run_command, "build_saber_runtime") as build:
            runtime = MagicMock()
            runtime.llm_client.enabled = False
            result = MagicMock()
            result.records = []
            result.observations = []
            result.status.value = "completed"
            runtime.orchestrator.run_mission.return_value = result
            build.return_value = runtime
            with patch.object(run_command, "persist_mission_result"):
                run_command.run_cli_mission(
                    target_value="dvwa", profile="web", agent_mode="deterministic", **overrides
                )
            return build.call_args.args[0]


def test_docker_network_threaded_from_env(monkeypatch):
    monkeypatch.setenv("SABER_DOCKER_NETWORK", "saber-lab")
    cfg = _run_capture_config()
    assert cfg.docker_network == "saber-lab"


def test_docker_network_defaults_to_host(monkeypatch):
    monkeypatch.delenv("SABER_DOCKER_NETWORK", raising=False)
    cfg = _run_capture_config()
    assert cfg.docker_network == "host"


def test_sandbox_image_threaded_from_env(monkeypatch):
    monkeypatch.setenv("SABER_SANDBOX_IMAGE", "example/img:tag")
    cfg = _run_capture_config()
    assert cfg.sandbox_image == "example/img:tag"
