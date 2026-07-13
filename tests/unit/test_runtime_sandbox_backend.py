"""Tests for runtime sandbox backend selection."""

from __future__ import annotations

from saber.core.docker_runner import DockerSubprocessRunner
from saber.core.runtime import SaberConfig, _build_sandbox
from saber.core.runtime import LocalSubprocessRunner


def test_build_sandbox_uses_docker_runner(tmp_path) -> None:
    config = SaberConfig(
        db_path=tmp_path / "saber.db",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        sandbox_backend="docker",
        sandbox_image="saber/sandbox:test",
        docker_network="bridge",
        docker_user="",
    )

    sandbox = _build_sandbox(config)

    assert isinstance(sandbox.runner, DockerSubprocessRunner)
    assert sandbox.runner.image == "saber/sandbox:test"
    assert sandbox.runner.network == "bridge"


def test_build_sandbox_uses_local_runner(tmp_path) -> None:
    config = SaberConfig(
        db_path=tmp_path / "saber.db",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        sandbox_backend="local",
    )

    sandbox = _build_sandbox(config)

    assert isinstance(sandbox.runner, LocalSubprocessRunner)


def test_saber_config_reads_docker_env(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_SANDBOX_BACKEND", "docker")
    monkeypatch.setenv("SABER_SANDBOX_IMAGE", "saber/sandbox:test")
    monkeypatch.setenv("SABER_DOCKER_NETWORK", "bridge")
    monkeypatch.setenv("SABER_DOCKER_USER", "1000:1000")

    config = SaberConfig.from_env()

    assert config.sandbox_backend == "docker"
    assert config.sandbox_image == "saber/sandbox:test"
    assert config.docker_network == "bridge"
    assert config.docker_user == "1000:1000"
