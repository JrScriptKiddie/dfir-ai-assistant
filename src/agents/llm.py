"""LLM provider abstraction.

Supports:
  - "ollama": local Ollama API
  - "openai": OpenAI-compatible chat completions
"""

from __future__ import annotations

import os
from typing import Protocol


class LLMProvider(Protocol):
    @property
    def model(self) -> str: ...

    def chat(self, messages: list[dict], temperature: float = 0.2) -> str: ...


class OllamaLLM:
    """Ollama chat completions via /api/chat (local) or /v1/chat/completions (cloud)."""

    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        self._model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:14b")
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._is_cloud = self.host.startswith("https://") or "ollama.com" in self.host

    @property
    def model(self) -> str:
        return self._model

    def chat(self, messages: list[dict], temperature: float = 0.2) -> str:
        import httpx

        if self._is_cloud:
            return self._chat_cloud(messages, temperature, httpx)
        return self._chat_local(messages, temperature, httpx)

    def _chat_local(self, messages, temperature, httpx):
        with httpx.Client(timeout=300) as client:
            resp = client.post(
                f"{self.host}/api/chat",
                json={
                    "model": self._model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    def _chat_cloud(self, messages, temperature, httpx):
        api_key = os.environ.get("OLLAMA_API_KEY", "")
        base = self.host.rstrip("/")
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        with httpx.Client(timeout=300) as client:
            resp = client.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": self._model,
                    "messages": messages,
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


class OpenAILLM:
    """OpenAI-compatible chat completions."""

    def __init__(
        self,
        model: str | None = None,
        api_base: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self._model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.api_base = api_base or os.environ.get(
            "OPENAI_API_BASE", "https://api.openai.com/v1"
        )
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    @property
    def model(self) -> str:
        return self._model

    def chat(self, messages: list[dict], temperature: float = 0.2) -> str:
        import httpx

        with httpx.Client(timeout=300) as client:
            resp = client.post(
                f"{self.api_base}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self._model,
                    "messages": messages,
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


def get_llm(backend: str | None = None, **kwargs) -> LLMProvider:
    backend = backend or os.environ.get("LLM_BACKEND", "ollama")
    if backend == "ollama":
        return OllamaLLM(model=kwargs.get("model"))
    if backend == "openai":
        return OpenAILLM(model=kwargs.get("model"))
    raise ValueError(f"unknown LLM backend: {backend}")