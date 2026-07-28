"""The LLM client retries transient transport/TLS errors before giving up."""

from __future__ import annotations

import ssl
import urllib.error
from unittest.mock import patch

from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider


def _client(max_retries: int = 5) -> LlmClient:
    return LlmClient(
        LlmConfig(
            provider=LlmProvider.OPENROUTER,
            model="m",
            api_key="k",
            base_url="https://openrouter.ai/api/v1",
            max_retries=max_retries,
        )
    )


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return b'{"ok": true}'


def test_retries_transient_ssl_then_succeeds():
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ssl.SSLError("[SSL: SSLV3_ALERT_BAD_RECORD_MAC] sslv3 alert bad record mac")
        return _FakeResponse()

    with patch("urllib.request.urlopen", side_effect=flaky), patch("time.sleep"):
        result = _client()._post_chat_completions({"messages": []})

    assert result == {"ok": True}
    assert calls["n"] == 3  # two transient failures, third succeeds


def test_gives_up_after_max_retries():
    def always_fail(*args, **kwargs):
        raise urllib.error.URLError("down")

    with patch("urllib.request.urlopen", side_effect=always_fail) as m, patch("time.sleep"):
        try:
            _client(max_retries=5)._post_chat_completions({"messages": []})
            raised = False
        except RuntimeError:
            raised = True

    assert raised
    assert m.call_count == 5  # exhausted all retries
