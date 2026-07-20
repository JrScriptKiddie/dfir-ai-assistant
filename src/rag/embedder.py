"""Embedder abstraction: text -> vectors.

Supports:
  - "dummy" : deterministic hash-based fake vectors for tests (no deps)
  - "ollama": Ollama embeddings API
  - "openai": OpenAI-compatible embeddings API
"""

from __future__ import annotations

import hashlib
import os
from typing import Protocol

import numpy as np


class Embedder(Protocol):
    """Embed text -> float32 vector (dim,)."""

    @property
    def dim(self) -> int: ...

    def embed(self, texts: list[str]) -> np.ndarray: ...


# ---- dummy embedder (for tests / offline) ----


class DummyEmbedder:
    """Deterministic hash-based embedding. No external deps.

    Useful for tests and bootstrapping the pipeline without an API.
    Not semantically meaningful but stable: same text -> same vector.
    """

    def __init__(self, dim: int = 256) -> None:
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self._dim), dtype=np.float32)
        for i, text in enumerate(texts):
            h = hashlib.sha256(text.encode("utf-8")).digest()
            # repeat hash to fill dim
            bytes_needed = self._dim * 4
            buf = b""
            counter = 0
            while len(buf) < bytes_needed:
                buf += hashlib.sha256(h + counter.to_bytes(4, "little")).digest()
                counter += 1
            arr = np.frombuffer(buf[:bytes_needed], dtype=np.uint8).astype(np.float32)
            out[i] = arr[: self._dim]
        return out


# ---- Ollama embedder ----


class OllamaEmbedder:
    """Ollama embeddings via /api/embeddings."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str | None = None,
    ) -> None:
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._dim: int | None = None

    @property
    def dim(self) -> int:
        if self._dim is None:
            v = self.embed(["test"])
            self._dim = v.shape[1]
        return self._dim  # type: ignore[return-value]

    def embed(self, texts: list[str]) -> np.ndarray:
        import httpx

        vecs: list[list[float]] = []
        with httpx.Client(timeout=60) as client:
            for text in texts:
                resp = client.post(
                    f"{self.host}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                )
                resp.raise_for_status()
                vecs.append(resp.json()["embedding"])
        return np.array(vecs, dtype=np.float32)


# ---- OpenAI-compatible embedder ----


class OpenAIEmbedder:
    """OpenAI-compatible embeddings (OpenAI, vLLM, etc.)."""

    def __init__(
        self,
        model: str = "text-embedding-3-small",
        api_base: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.api_base = api_base or os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._dim: int | None = None

    @property
    def dim(self) -> int:
        if self._dim is None:
            v = self.embed(["test"])
            self._dim = v.shape[1]
        return self._dim  # type: ignore[return-value]

    def embed(self, texts: list[str]) -> np.ndarray:
        import httpx

        with httpx.Client(timeout=60) as client:
            resp = client.post(
                f"{self.api_base}/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
        vecs = [item["embedding"] for item in data["data"]]
        return np.array(vecs, dtype=np.float32)


# ---- factory ----


def get_embedder(backend: str | None = None, **kwargs) -> Embedder:
    backend = backend or os.environ.get("EMBEDDER_BACKEND", "dummy")
    if backend == "dummy":
        return DummyEmbedder(dim=kwargs.get("dim", 256))
    if backend == "tfidf":
        from .tfidf_embedder import TfidfEmbedder
        return TfidfEmbedder(dim=kwargs.get("dim", 512))
    if backend == "ollama":
        return OllamaEmbedder(model=kwargs.get("model", "nomic-embed-text"))
    if backend == "openai":
        return OpenAIEmbedder(model=kwargs.get("model", "text-embedding-3-small"))
    raise ValueError(f"unknown embedder backend: {backend}")