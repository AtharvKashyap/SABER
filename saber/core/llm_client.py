"""Environment-driven LLM client for SABER agents.

Supports OpenAI-compatible APIs:
- OpenAI
- OpenRouter
- LiteLLM
- vLLM OpenAI-compatible server
- Ollama OpenAI-compatible endpoint
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class LlmProvider(StrEnum):
    """Supported provider modes."""

    DISABLED = "disabled"
    OPENAI_COMPATIBLE = "openai_compatible"


@dataclass(frozen=True)
class LlmConfig:
    """LLM configuration loaded from .env/environment."""

    provider: LlmProvider = LlmProvider.DISABLED
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: int = 60
    max_retries: int = 3
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "LlmConfig":
        """Load LLM config from environment variables."""

        api_key = (
            os.getenv("SABER_LLM_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
        )

        provider_raw = os.getenv("SABER_LLM_PROVIDER", "").strip().lower()

        if provider_raw:
            provider = LlmProvider(provider_raw)
        elif api_key:
            provider = LlmProvider.OPENAI_COMPATIBLE
        else:
            provider = LlmProvider.DISABLED

        extra_headers: dict[str, str] = {}

        referer = os.getenv("SABER_LLM_HTTP_REFERER", "").strip()
        app_title = os.getenv("SABER_LLM_APP_TITLE", "").strip()

        if referer:
            extra_headers["HTTP-Referer"] = referer
        if app_title:
            extra_headers["X-Title"] = app_title

        return cls(
            provider=provider,
            api_key=api_key,
            base_url=os.getenv("SABER_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            model=os.getenv("SABER_LLM_MODEL", "gpt-4o-mini"),
            temperature=float(os.getenv("SABER_LLM_TEMPERATURE", "0.1")),
            max_tokens=int(os.getenv("SABER_LLM_MAX_TOKENS", "2000")),
            timeout_seconds=int(os.getenv("SABER_LLM_TIMEOUT_SECONDS", "60")),
            max_retries=int(os.getenv("SABER_LLM_MAX_RETRIES", "3")),
            extra_headers=extra_headers,
        )

    @property
    def enabled(self) -> bool:
        """Return whether the client can make LLM calls."""

        return self.provider != LlmProvider.DISABLED and bool(self.api_key)


@dataclass(frozen=True)
class LlmResponse:
    """Normalized LLM response."""

    content: str
    model: str
    provider: str
    raw: dict[str, Any] = field(default_factory=dict)

    def parse_json(self) -> dict[str, Any]:
        """Parse response content as JSON, including fenced JSON."""

        text = self.content.strip()

        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        return json.loads(text)


class LlmClient:
    """Small provider-neutral LLM client."""

    def __init__(self, config: LlmConfig | None = None) -> None:
        self.config = config or LlmConfig.from_env()

    @property
    def enabled(self) -> bool:
        """Return whether LLM calls are enabled."""

        return self.config.enabled

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LlmResponse:
        """Run a chat completion."""

        if not self.enabled:
            raise RuntimeError("LLM is disabled or SABER_LLM_API_KEY is missing.")

        if self.config.provider == LlmProvider.OPENAI_COMPATIBLE:
            return self._complete_openai_compatible(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=model or self.config.model,
                temperature=self.config.temperature if temperature is None else temperature,
                max_tokens=self.config.max_tokens if max_tokens is None else max_tokens,
                metadata=metadata or {},
            )

        raise RuntimeError(f"Unsupported LLM provider: {self.config.provider}")

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run a chat completion and parse the result as JSON."""

        return self.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            metadata=metadata,
        ).parse_json()

    def _complete_openai_compatible(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model: str,
        temperature: float,
        max_tokens: int,
        metadata: dict[str, Any],
    ) -> LlmResponse:
        """Call /chat/completions on an OpenAI-compatible endpoint."""

        url = f"{self.config.base_url}/chat/completions"

        payload = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "metadata": metadata,
        }

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            **self.config.extra_headers,
        }

        last_error: Exception | None = None

        for attempt in range(1, self.config.max_retries + 1):
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            try:
                with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                    raw = json.loads(response.read().decode("utf-8"))

                content = _extract_openai_content(raw)

                return LlmResponse(
                    content=content,
                    model=raw.get("model") or model,
                    provider=self.config.provider.value,
                    raw=raw,
                )

            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                last_error = RuntimeError(f"LLM HTTP error {exc.code}: {body}")

                if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                    raise last_error from exc

            except urllib.error.URLError as exc:
                last_error = RuntimeError(f"LLM connection error: {exc}")

            if attempt < self.config.max_retries:
                time.sleep(min(2 ** (attempt - 1), 8))

        raise RuntimeError(f"LLM request failed after {self.config.max_retries} attempts: {last_error}")


class DisabledLlmClient(LlmClient):
    """Explicit disabled client."""

    def __init__(self) -> None:
        super().__init__(LlmConfig(provider=LlmProvider.DISABLED))

    def complete(self, **kwargs: Any) -> LlmResponse:
        raise RuntimeError("LLM is disabled.")

    def complete_json(self, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("LLM is disabled.")


def _extract_openai_content(raw: dict[str, Any]) -> str:
    """Extract assistant content from OpenAI-compatible response JSON."""

    choices = raw.get("choices") or []
    if not choices:
        raise RuntimeError("LLM response did not include choices.")

    message = choices[0].get("message") or {}
    content = message.get("content")

    if content is None:
        raise RuntimeError("LLM response did not include message.content.")

    return str(content)
