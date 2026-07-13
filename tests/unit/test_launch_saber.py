"""Tests for SABER launcher."""

from __future__ import annotations

import os
import subprocess

import pytest

from scripts.launch_saber import (
    LaunchConfig,
    clean_env_value,
    docker_image_exists,
    ensure_sandbox_image,
    load_dotenv,
    parse_args,
    pull_sandbox_image,
)


def test_clean_env_value_removes_matching_quotes() -> None:
    assert clean_env_value('"hello"') == "hello"
    assert clean_env_value("'hello'") == "hello"
    assert clean_env_value("hello") == "hello"


def test_load_dotenv_does_not_override_existing(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SABER_MODEL=local:test\nSABER_LOG_LEVEL=DEBUG\n", encoding="utf-8")

    monkeypatch.setenv("SABER_MODEL", "existing:model")

    loaded = load_dotenv(env_file)

    assert loaded["SABER_MODEL"] == "local:test"
    assert loaded["SABER_LOG_LEVEL"] == "DEBUG"
    assert os.environ["SABER_MODEL"] == "existing:model"


def test_load_dotenv_missing_file_returns_empty(tmp_path) -> None:
    assert load_dotenv(tmp_path / ".env.missing") == {}


def test_parse_args_defaults(monkeypatch) -> None:
    monkeypatch.delenv("SABER_UI_HOST", raising=False)
    monkeypatch.delenv("SABER_UI_PORT", raising=False)

    args = parse_args([])

    assert args.host == "127.0.0.1"
    assert args.port == 8000
    assert args.no_browser is False
    assert args.build_image is False
    assert args.install_docker is False
    assert args.no_pull is False


def test_parse_args_install_docker() -> None:
    args = parse_args(["--install-docker"])

    assert args.install_docker is True


def test_parse_args_no_pull() -> None:
    args = parse_args(["--no-pull"])

    assert args.no_pull is True


def test_launch_config_ui_url() -> None:
    config = LaunchConfig(
        host="127.0.0.1",
        port=9000,
        open_browser=True,
        build_image=False,
        install_docker=False,
        no_pull=False,
        backend="docker",
        image="ghcr.io/example/saber:test",
    )

    assert config.ui_url == "http://127.0.0.1:9000/ui"


def test_docker_image_exists_true(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert docker_image_exists("saber/sandbox:test") is True


def test_docker_image_exists_false(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert docker_image_exists("saber/sandbox:test") is False


def test_pull_sandbox_image_success(monkeypatch) -> None:
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert pull_sandbox_image("ghcr.io/example/saber:test") is True
    assert calls[0] == ["docker", "pull", "ghcr.io/example/saber:test"]


def test_ensure_sandbox_image_accepts_existing_image(monkeypatch) -> None:
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    ensure_sandbox_image("saber/sandbox:test", build=False, pull=True)

    assert calls[0] == ["docker", "image", "inspect", "saber/sandbox:test"]


def test_ensure_sandbox_image_pulls_missing_image(monkeypatch) -> None:
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        if cmd[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 1)

        if cmd[:2] == ["docker", "pull"]:
            return subprocess.CompletedProcess(cmd, 0)

        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    ensure_sandbox_image("ghcr.io/example/saber:test", build=False, pull=True)

    assert ["docker", "pull", "ghcr.io/example/saber:test"] in calls


def test_ensure_sandbox_image_missing_without_pull_or_build_exits(monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        ensure_sandbox_image("saber/sandbox:test", build=False, pull=False)

    assert exc.value.code == 2
