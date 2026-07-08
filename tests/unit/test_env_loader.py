"""Tests for SABER .env loader."""

from __future__ import annotations

from saber.core.env_loader import load_env_file


def test_load_env_file_does_not_override_by_default(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SABER_LLM_MODEL=file-model\nQUOTED='hello world'\n", encoding="utf-8")

    monkeypatch.setenv("SABER_LLM_MODEL", "existing-model")

    loaded = load_env_file(env_file)

    assert loaded["SABER_LLM_MODEL"] == "file-model"
    assert loaded["QUOTED"] == "hello world"
    assert __import__("os").environ["SABER_LLM_MODEL"] == "existing-model"


def test_load_env_file_can_override(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SABER_LLM_MODEL=file-model\n", encoding="utf-8")

    monkeypatch.setenv("SABER_LLM_MODEL", "existing-model")

    load_env_file(env_file, override=True)

    assert __import__("os").environ["SABER_LLM_MODEL"] == "file-model"
