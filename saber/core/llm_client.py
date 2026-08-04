"""LLM client for SABER agent decisions."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any

from saber.core.env_loader import load_env_file

try:  # pragma: no cover - certifi is a normal dependency; guard is belt-and-suspenders
    import certifi

    _CA_BUNDLE: str | None = certifi.where()
except Exception:  # noqa: BLE001
    _CA_BUNDLE = None


@lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    """Return a TLS context that trusts a real CA bundle.

    On some Python installs (notably macOS framework/venv builds) the stdlib
    default context has no usable CA store, so ``urlopen`` fails every HTTPS
    request with ``CERTIFICATE_VERIFY_FAILED`` — which silently turned every
    LLM-mode mission into a no-op. Using certifi's bundle fixes this portably
    while keeping certificate verification ON.
    """

    if _CA_BUNDLE:
        return ssl.create_default_context(cafile=_CA_BUNDLE)
    return ssl.create_default_context()


class LlmProvider(StrEnum):
    """Supported model routing modes."""

    DISABLED = "disabled"
    OPENROUTER = "openrouter"
    LOCAL = "local"


@dataclass(frozen=True)
class LlmConfig:
    """Configuration for SABER model decisions."""

    provider: LlmProvider = LlmProvider.DISABLED
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: int = 60
    max_retries: int = 5

    @property
    def enabled(self) -> bool:
        """Return whether model calls are enabled."""

        return self.provider != LlmProvider.DISABLED and bool(self.model)

    @classmethod
    def from_env(cls) -> "LlmConfig":
        """Load SABER model config from .env/environment variables."""

        load_env_file()

        raw_model = os.getenv("SABER_MODEL", "disabled").strip()

        if not raw_model or raw_model.lower() == "disabled":
            return cls(provider=LlmProvider.DISABLED)

        if ":" not in raw_model:
            raise ValueError(
                "SABER_MODEL must be one of: disabled, openrouter:<model>, local:<model>."
            )

        prefix, model = raw_model.split(":", 1)
        prefix = prefix.strip().lower()
        model = model.strip()

        if not model:
            raise ValueError("SABER_MODEL is missing a model name.")

        if prefix == LlmProvider.OPENROUTER.value:
            return cls(
                provider=LlmProvider.OPENROUTER,
                model=model,
                api_key=os.getenv("SABER_MODEL_API_KEY", "").strip(),
                base_url="https://openrouter.ai/api/v1",
            )

        if prefix == LlmProvider.LOCAL.value:
            base_url = os.getenv("SABER_LOCAL_MODEL_URL", "").strip()
            if not base_url:
                raise ValueError("SABER_LOCAL_MODEL_URL is required when SABER_MODEL=local:<model>.")
            return cls(
                provider=LlmProvider.LOCAL,
                model=model,
                api_key=os.getenv("SABER_MODEL_API_KEY", "").strip(),
                base_url=base_url.rstrip("/"),
            )

        raise ValueError(
            "Unsupported SABER_MODEL prefix. Use disabled, openrouter:<model>, or local:<model>."
        )


@dataclass(frozen=True)
class LlmResponse:
    """Raw model response."""

    content: str
    model: str
    metadata: dict[str, Any]

    def parse_json(self) -> dict[str, Any]:
        """Parse JSON from a model response, including fenced JSON."""

        text = self.content.strip()

        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        return json.loads(text)


class LlmClient:
    """Small dependency-free chat-completions client."""

    def __init__(self, config: LlmConfig | None = None) -> None:
        """Initialize client."""

        self.config = config or LlmConfig.from_env()

    @property
    def enabled(self) -> bool:
        """Return whether this client can make model calls."""

        return self.config.enabled

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        metadata: dict[str, Any] | None = None,
    ) -> LlmResponse:
        """Run a chat-completions request."""

        if not self.enabled:
            raise RuntimeError("Model client is disabled.")

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        response_payload = self._post_chat_completions(payload)
        choices = response_payload.get("choices") or []

        if not choices:
            raise RuntimeError("Model response did not include choices.")

        message = choices[0].get("message") or {}
        content = message.get("content") or ""

        if not content.strip():
            raise RuntimeError("Model response content was empty.")

        return LlmResponse(
            content=content,
            model=str(response_payload.get("model") or self.config.model),
            metadata={
                "provider": self.config.provider.value,
                "request_metadata": metadata or {},
                "usage": response_payload.get("usage") or {},
            },
        )

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run completion and parse strict JSON."""

        return self.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            metadata=metadata,
        ).parse_json()

    def _post_chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to a chat-completions-compatible endpoint."""

        if not self.config.base_url:
            raise RuntimeError("Model base URL is not configured.")

        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }

        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        last_error: Exception | None = None

        for attempt in range(self.config.max_retries):
            request = urllib.request.Request(url=url, data=body, headers=headers, method="POST")

            try:
                with urllib.request.urlopen(
                    request, timeout=self.config.timeout_seconds, context=_ssl_context()
                ) as response:
                    raw = response.read().decode("utf-8")
                    return json.loads(raw)
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                    detail = exc.read().decode("utf-8", errors="replace")
                    raise RuntimeError(f"Model request failed with HTTP {exc.code}: {detail}") from exc
            except (urllib.error.URLError, ssl.SSLError, TimeoutError) as exc:
                # Transient transport errors, incl. intermittent TLS record
                # corruption (SSLV3_ALERT_BAD_RECORD_MAC). Retry with backoff.
                last_error = exc

            if attempt < self.config.max_retries - 1:
                time.sleep(min(0.75 * (2**attempt), 8.0))

        raise RuntimeError(f"Model request failed after retries: {last_error}") from last_error


class DisabledLlmClient(LlmClient):
    """Disabled client useful for tests."""

    def __init__(self) -> None:
        """Initialize disabled client."""

        super().__init__(LlmConfig(provider=LlmProvider.DISABLED))
