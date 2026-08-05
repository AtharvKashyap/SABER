"""Prompt caching on the static half of the decision prompt.

Measured on a 20-step mission with a web-scoped catalog: 6,085 of 9,775 prompt
tokens are byte-identical on every decision — the instructions plus the tool
catalog. Cache reads bill at a fraction of fresh input, so caching that prefix is
the single largest cost saving available without touching what the model reasons
about.

The marker is only sent to models that understand it. That restraint is the point
of most of these tests: a provider answering 400 to an unknown field would fail
the decision, and a failed decision fails the whole mission.
"""

from __future__ import annotations

import json

import pytest
from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider

# Long enough to clear the provider's caching minimum.
BIG_PROMPT = "You are a decision engine.\n" + ("tool nmap: scan a host\n" * 400)


def _client(model: str, *, prompt_cache: bool = True) -> LlmClient:
    return LlmClient(
        LlmConfig(
            provider=LlmProvider.OPENROUTER,
            model=model,
            base_url="https://example.invalid/v1",
            prompt_cache=prompt_cache,
        )
    )


def test_anthropic_models_get_a_cache_control_marker() -> None:
    content = _client("anthropic/claude-sonnet-4.5")._system_content(BIG_PROMPT)

    assert isinstance(content, list)
    assert content[0]["cache_control"] == {"type": "ephemeral"}
    assert content[0]["text"] == BIG_PROMPT


@pytest.mark.parametrize(
    "model",
    ["openai/gpt-4o", "google/gemini-2.0-flash", "meta-llama/llama-3-70b", "mistral/large"],
)
def test_other_models_get_a_plain_string(model: str) -> None:
    """An unrecognised field is a 400, which would fail the mission.

    OpenAI-family models cache a stable prefix automatically with no marker, so
    nothing is lost by staying conservative here.
    """

    content = _client(model)._system_content(BIG_PROMPT)

    assert isinstance(content, str)
    assert content == BIG_PROMPT


def test_the_kill_switch_disables_the_marker() -> None:
    content = _client("anthropic/claude-sonnet-4.5", prompt_cache=False)._system_content(BIG_PROMPT)

    assert isinstance(content, str)


def test_a_prompt_too_small_to_cache_is_not_marked() -> None:
    """Below the provider minimum the marker buys nothing, so it is noise."""

    content = _client("anthropic/claude-sonnet-4.5")._system_content("short prompt")

    assert isinstance(content, str)


def test_the_request_body_is_serializable_either_way() -> None:
    """Whatever shape the system message takes, it has to survive json.dumps."""

    for model in ("anthropic/claude-sonnet-4.5", "openai/gpt-4o"):
        content = _client(model)._system_content(BIG_PROMPT)
        body = json.dumps(
            {"model": model, "messages": [{"role": "system", "content": content}]}
        )
        assert json.loads(body)["messages"][0]["content"] == content


def test_env_kill_switch_is_read() -> None:
    import os
    from unittest.mock import patch

    with patch.dict(os.environ, {"SABER_MODEL": "openrouter:anthropic/claude-sonnet-4.5",
                                 "SABER_MODEL_API_KEY": "k",
                                 "SABER_PROMPT_CACHE": "0"}, clear=False):
        assert LlmConfig.from_env().prompt_cache is False

    with patch.dict(os.environ, {"SABER_MODEL": "openrouter:anthropic/claude-sonnet-4.5",
                                 "SABER_MODEL_API_KEY": "k",
                                 "SABER_PROMPT_CACHE": "1"}, clear=False):
        assert LlmConfig.from_env().prompt_cache is True


def test_caching_defaults_on() -> None:
    """The saving is large and the fallbacks are safe, so it should not need opting in."""

    assert LlmConfig().prompt_cache is True
