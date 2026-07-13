"""Tests for Docker runner."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from saber.core.docker_runner import DockerSubprocessRunner


def test_docker_runner_builds_basic_command(tmp_path) -> None:
    runner = DockerSubprocessRunner(
        image="saber/sandbox:test",
        repo_dir=tmp_path,
        network="bridge",
        user="",
        cap_add=("NET_RAW",),
    )

    command = runner.build_docker_command(command=["nmap", "--version"])

    assert command[:3] == ["docker", "run", "--rm"]
    assert ["--network", "bridge"] == command[3:5]
    assert "--cap-add" in command
    assert "-v" in command
    assert "saber/sandbox:test" in command
    assert command[-2:] == ["nmap", "--version"]


def test_docker_runner_maps_repo_local_paths(tmp_path) -> None:
    output_file = tmp_path / "runs" / "evidence" / "nmap.xml"
    output_file.parent.mkdir(parents=True)

    runner = DockerSubprocessRunner(
        image="saber/sandbox:test",
        repo_dir=tmp_path,
        network="bridge",
        cap_add=(),
    )

    command = runner.build_docker_command(
        command=["nmap", "-oX", str(output_file), "127.0.0.1"]
    )

    assert "/workspace/runs/evidence/nmap.xml" in command
    assert str(output_file) not in command


def test_docker_runner_maps_working_directory(tmp_path) -> None:
    workdir = tmp_path / "runs"
    workdir.mkdir()

    runner = DockerSubprocessRunner(
        image="saber/sandbox:test",
        repo_dir=tmp_path,
        network="bridge",
        cap_add=(),
    )

    command = runner.build_docker_command(
        command=["pwd"],
        working_directory=workdir,
    )

    workdir_index = command.index("-w") + 1
    assert command[workdir_index] == "/workspace/runs"


def test_docker_runner_rejects_empty_command(tmp_path) -> None:
    runner = DockerSubprocessRunner(repo_dir=tmp_path)

    with pytest.raises(ValueError, match="empty"):
        runner.build_docker_command(command=[])


def test_docker_runner_executes_docker_command(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    runner = DockerSubprocessRunner(
        image="saber/sandbox:test",
        repo_dir=tmp_path,
        network="bridge",
        cap_add=(),
    )

    result = runner.run(["echo", "hello"])

    assert result.return_code == 0
    assert result.stdout == "ok"
    assert result.metadata["runner"] == "docker_subprocess"
    assert calls[0][0][0:3] == ["docker", "run", "--rm"]
