"""Tests for SABER LLM client."""

from __future__ import annotations

import json
import urllib.request

import pytest

from saber.core.llm_client import DisabledLlmClient, LlmClient, LlmConfig, LlmProvider, LlmResponse


def test_config_disabled_from_env(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_MODEL", "disabled")

    config = LlmConfig.from_env()

    assert config.provider == LlmProvider.DISABLED
    assert config.enabled is False


def test_config_openrouter_from_env(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_MODEL", "openrouter:anthropic/claude-3.5-sonnet")
    monkeypatch.setenv("SABER_MODEL_API_KEY", "test-key")

    config = LlmConfig.from_env()

    assert config.provider == LlmProvider.OPENROUTER
    assert config.model == "anthropic/claude-3.5-sonnet"
    assert config.api_key == "test-key"
    assert config.base_url == "https://openrouter.ai/api/v1"
    assert config.enabled is True


def test_config_local_from_env(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_MODEL", "local:llama3.1:8b")
    monkeypatch.setenv("SABER_LOCAL_MODEL_URL", "http://127.0.0.1:11434/v1")

    config = LlmConfig.from_env()

    assert config.provider == LlmProvider.LOCAL
    assert config.model == "llama3.1:8b"
    assert config.base_url == "http://127.0.0.1:11434/v1"
    assert config.enabled is True


def test_config_local_requires_url(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_MODEL", "local:llama3.1:8b")
    monkeypatch.delenv("SABER_LOCAL_MODEL_URL", raising=False)

    with pytest.raises(ValueError, match="SABER_LOCAL_MODEL_URL"):
        LlmConfig.from_env()


def test_config_rejects_unknown_model_prefix(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SABER_MODEL", "weird:model")

    with pytest.raises(ValueError, match="Unsupported SABER_MODEL"):
        LlmConfig.from_env()


def test_disabled_client_raises() -> None:
    client = DisabledLlmClient()

    with pytest.raises(RuntimeError, match="disabled"):
        client.complete(system_prompt="system", user_prompt="user")


def test_response_parse_plain_json() -> None:
    response = LlmResponse(
        content='{"decision": "run_tool"}',
        model="test",
        metadata={},
    )

    assert response.parse_json() == {"decision": "run_tool"}


def test_response_parse_fenced_json() -> None:
    response = LlmResponse(
        content='```json\n{"decision": "run_tool"}\n```',
        model="test",
        metadata={},
    )

    assert response.parse_json() == {"decision": "run_tool"}


def test_client_posts_chat_completion(monkeypatch) -> None:
    captured = {}

    class FakeHTTPResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "model": "anthropic/claude-3.5-sonnet",
                    "choices": [
                        {
                            "message": {
                                "content": '{"decision": "run_tool"}',
                            }
                        }
                    ],
                    "usage": {"total_tokens": 10},
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout, context=None):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        captured["context"] = context
        return FakeHTTPResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = LlmClient(
        LlmConfig(
            provider=LlmProvider.OPENROUTER,
            model="anthropic/claude-3.5-sonnet",
            api_key="test-key",
            base_url="https://openrouter.ai/api/v1",
            timeout_seconds=12,
        )
    )

    result = client.complete_json(system_prompt="system", user_prompt="user")

    assert result == {"decision": "run_tool"}
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["payload"]["model"] == "anthropic/claude-3.5-sonnet"
    assert captured["payload"]["messages"][0]["role"] == "system"
    assert captured["payload"]["messages"][1]["role"] == "user"
    assert captured["timeout"] == 12
