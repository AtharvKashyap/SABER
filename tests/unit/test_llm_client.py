"""Tests for SABER LLM client."""

from __future__ import annotations

import json
import urllib.error

import pytest

from saber.core.llm_client import DisabledLlmClient, LlmClient, LlmConfig, LlmProvider


def test_llm_config_disabled_without_key(monkeypatch) -> None:
    monkeypatch.delenv("SABER_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SABER_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    config = LlmConfig.from_env()

    assert config.provider == LlmProvider.DISABLED
    assert config.enabled is False


def test_llm_config_enabled_with_saber_key(monkeypatch) -> None:
    monkeypatch.setenv("SABER_LLM_API_KEY", "test-key")
    monkeypatch.setenv("SABER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SABER_LLM_MODEL", "test-model")
    monkeypatch.setenv("SABER_LLM_TEMPERATURE", "0.2")
    monkeypatch.setenv("SABER_LLM_MAX_TOKENS", "1234")
    monkeypatch.setenv("SABER_LLM_TIMEOUT_SECONDS", "12")
    monkeypatch.setenv("SABER_LLM_MAX_RETRIES", "2")

    config = LlmConfig.from_env()

    assert config.provider == LlmProvider.OPENAI_COMPATIBLE
    assert config.enabled is True
    assert config.api_key == "test-key"
    assert config.base_url == "https://example.test/v1"
    assert config.model == "test-model"
    assert config.temperature == 0.2
    assert config.max_tokens == 1234
    assert config.timeout_seconds == 12
    assert config.max_retries == 2


def test_llm_config_supports_openrouter_headers(monkeypatch) -> None:
    monkeypatch.setenv("SABER_LLM_API_KEY", "test-key")
    monkeypatch.setenv("SABER_LLM_HTTP_REFERER", "https://example.com")
    monkeypatch.setenv("SABER_LLM_APP_TITLE", "SABER Test")

    config = LlmConfig.from_env()

    assert config.extra_headers["HTTP-Referer"] == "https://example.com"
    assert config.extra_headers["X-Title"] == "SABER Test"


def test_disabled_client_raises() -> None:
    client = DisabledLlmClient()

    assert client.enabled is False

    with pytest.raises(RuntimeError, match="disabled"):
        client.complete(system_prompt="x", user_prompt="y")


def test_parse_json_tolerates_fenced_json() -> None:
    config = LlmConfig(
        provider=LlmProvider.OPENAI_COMPATIBLE,
        api_key="test-key",
        base_url="https://example.test/v1",
    )
    client = LlmClient(config)

    response = type(
        "FakeResponse",
        (),
        {
            "content": '```json\n{"decision":"stop"}\n```',
            "parse_json": lambda self: json.loads('{"decision":"stop"}'),
        },
    )()

    assert response.parse_json() == {"decision": "stop"}


def test_openai_compatible_request_is_normalized(monkeypatch) -> None:
    captured = {}

    class FakeHTTPResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "model": "test-model",
                    "choices": [
                        {
                            "message": {
                                "content": '{"decision":"stop"}',
                            }
                        }
                    ],
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeHTTPResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    client = LlmClient(
        LlmConfig(
            provider=LlmProvider.OPENAI_COMPATIBLE,
            api_key="test-key",
            base_url="https://example.test/v1",
            model="test-model",
            timeout_seconds=7,
        )
    )

    response = client.complete(system_prompt="system", user_prompt="user")

    assert response.content == '{"decision":"stop"}'
    assert response.model == "test-model"
    assert captured["url"] == "https://example.test/v1/chat/completions"
    assert captured["payload"]["model"] == "test-model"
    assert captured["payload"]["messages"][0]["role"] == "system"
    assert captured["payload"]["messages"][1]["role"] == "user"
    assert captured["timeout"] == 7
