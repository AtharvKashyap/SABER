"""Tests for SABER .env loader."""

from __future__ import annotations

import os

from saber.core.env_loader import load_env_file


def test_load_env_file_does_not_override_existing_by_default(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SABER_MODEL=file-model\nQUOTED='hello world'\n", encoding="utf-8")

    monkeypatch.setenv("SABER_MODEL", "existing-model")

    loaded = load_env_file(env_file)

    assert loaded["SABER_MODEL"] == "file-model"
    assert loaded["QUOTED"] == "hello world"
    assert os.environ["SABER_MODEL"] == "existing-model"


def test_load_env_file_can_override(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SABER_MODEL=file-model\n", encoding="utf-8")

    monkeypatch.setenv("SABER_MODEL", "existing-model")

    loaded = load_env_file(env_file, override=True)

    assert loaded["SABER_MODEL"] == "file-model"
    assert os.environ["SABER_MODEL"] == "file-model"


def test_load_missing_env_file_returns_empty(tmp_path) -> None:
    loaded = load_env_file(tmp_path / ".env.missing")

    assert loaded == {}
