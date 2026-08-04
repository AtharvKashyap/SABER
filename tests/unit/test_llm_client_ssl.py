"""The LLM client must verify TLS with a real CA bundle.

Regression: on macOS venv Python installs the stdlib default SSL context has no
usable CA store, so urlopen failed HTTPS with CERTIFICATE_VERIFY_FAILED and every
mission terminated doing nothing. The client must pass an ssl.SSLContext to
urlopen so verification succeeds portably.
"""

from __future__ import annotations

import json
import ssl
from unittest.mock import patch

from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(
            {"choices": [{"message": {"content": "{}"}}], "model": "test"}
        ).encode("utf-8")


def _client() -> LlmClient:
    return LlmClient(
        LlmConfig(
            provider=LlmProvider.OPENROUTER,
            model="test-model",
            api_key="test-key",
            base_url="https://openrouter.ai/api/v1",
            max_retries=1,
        )
    )


def test_post_passes_ssl_context_to_urlopen():
    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as mock_urlopen:
        _client()._post_chat_completions({"messages": []})

    assert mock_urlopen.called
    _, kwargs = mock_urlopen.call_args
    ctx = kwargs.get("context")
    assert isinstance(ctx, ssl.SSLContext), "urlopen must be called with an ssl.SSLContext"
