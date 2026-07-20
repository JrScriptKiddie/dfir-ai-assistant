"""turboVEC - lightweight vector store for DFIR AI Assistant.

Design (ADR-003): numpy matrix + JSON sidecar with metadata.
Optional FAISS IndexFlatIP backend when available for speed on large cases.

One index = one directory:
  turbovec/
    vectors.npy          # (N, dim) float32, L2-normalized
    meta.jsonl           # one JSON per row: {id, text, metadata...}
    index.json           # {dim, n, case_id, created_at, embedding_model}
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np


@dataclass
class Chunk:
    """One RAG element: event or wiki paragraph."""

    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Hit:
    """One retrieval result."""

    chunk: Chunk
    score: float


class TurboVec:
    """In-memory vector store with persistence.

    Vectors are L2-normalized so cosine similarity = dot product.
    Supports metadata filtering post-retrieval.
    """

    def __init__(
        self,
        dim: int | None = None,
        case_id: str | None = None,
        embedding_model: str = "unknown",
    ) -> None:
        self.dim = dim
        self.case_id = case_id
        self.embedding_model = embedding_model
        self._vectors: np.ndarray | None = None  # (N, dim) float32
        self._chunks: list[Chunk] = []
        self._id_to_row: dict[str, int] = {}

    # ---- core ops ----

    def add(self, chunks: list[Chunk], embeddings: np.ndarray) -> None:
        """Add chunks with pre-computed embeddings (N, dim)."""
        if embeddings.ndim != 2:
            raise ValueError(f"embeddings must be 2D, got {embeddings.ndim}D")
        if self.dim is None:
            self.dim = embeddings.shape[1]
        elif embeddings.shape[1] != self.dim:
            raise ValueError(
                f"embedding dim {embeddings.shape[1]} != store dim {self.dim}"
            )
        normed = _l2_normalize(embeddings.astype(np.float32))
        if self._vectors is None:
            self._vectors = normed.copy()
        else:
            self._vectors = np.vstack([self._vectors, normed])
        for i, chunk in enumerate(chunks):
            if chunk.id in self._id_to_row:
                # replace existing
                row = self._id_to_row[chunk.id]
                self._vectors[row] = normed[i]
                self._chunks[row] = chunk
            else:
                self._id_to_row[chunk.id] = len(self._chunks)
                self._chunks.append(chunk)

    def query(
        self,
        embedding: np.ndarray,
        k: int = 10,
        filters: dict[str, Any] | None = None,
    ) -> list[Hit]:
        """Top-k cosine search with optional metadata filters."""
        if self._vectors is None or len(self._chunks) == 0:
            return []
        q = _l2_normalize(embedding.astype(np.float32).reshape(1, -1))
        scores = (self._vectors @ q.T).ravel()  # cosine (both normalized)
        # apply filters
        if filters:
            mask = np.array(
                [_matches(c.metadata, filters) for c in self._chunks],
                dtype=bool,
            )
            scores = np.where(mask, scores, -1.0)
        k = min(k, len(scores))
        if k == 0:
            return []
        top_idx = np.argpartition(-scores, k - 1)[:k]
        top_idx = top_idx[np.argsort(-scores[top_idx])]
        hits: list[Hit] = []
        for idx in top_idx:
            if scores[idx] < 0:
                continue
            hits.append(Hit(chunk=self._chunks[idx], score=float(scores[idx])))
        return hits

    def get(self, chunk_id: str) -> Chunk | None:
        row = self._id_to_row.get(chunk_id)
        if row is None:
            return None
        return self._chunks[row]

    def keyword_search(
        self,
        keywords: list[str],
        k: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[Hit]:
        """Keyword-based search: matches chunks containing ANY of the keywords.

        Case-insensitive substring match. Returns hits sorted by number of
        keyword matches (more matches = higher relevance).
        """
        if not self._chunks:
            return []
        kws_lower = [kw.lower() for kw in keywords]
        results: list[Hit] = []
        for chunk in self._chunks:
            if filters and not _matches(chunk.metadata, filters):
                continue
            text_lower = chunk.text.lower()
            match_count = sum(1 for kw in kws_lower if kw in text_lower)
            if match_count > 0:
                # score = normalized match count
                score = match_count / len(kws_lower)
                results.append(Hit(chunk=chunk, score=score))
        results.sort(key=lambda h: -h.score)
        return results[:k]

    def stats(self) -> dict[str, Any]:
        return {
            "n_vectors": len(self._chunks),
            "dim": self.dim,
            "case_id": self.case_id,
            "embedding_model": self.embedding_model,
            "created_at": getattr(self, "_created_at", None),
        }

    # ---- persistence ----

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        if self._vectors is not None:
            np.save(p / "vectors.npy", self._vectors)
        with open(p / "meta.jsonl", "w", encoding="utf-8") as f:
            for chunk in self._chunks:
                f.write(chunk.to_jsonl() + "\n")
        index_meta = {
            "dim": self.dim,
            "n": len(self._chunks),
            "case_id": self.case_id,
            "embedding_model": self.embedding_model,
            "created_at": time.time(),
        }
        with open(p / "index.json", "w", encoding="utf-8") as f:
            json.dump(index_meta, f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> "TurboVec":
        p = Path(path)
        with open(p / "index.json", encoding="utf-8") as f:
            idx = json.load(f)
        store = cls(
            dim=idx["dim"],
            case_id=idx.get("case_id"),
            embedding_model=idx.get("embedding_model", "unknown"),
        )
        store._created_at = idx.get("created_at")
        vec_path = p / "vectors.npy"
        if vec_path.exists():
            store._vectors = np.load(vec_path)
        store._chunks = []
        with open(p / "meta.jsonl", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                store._chunks.append(
                    Chunk(id=obj["id"], text=obj["text"], metadata=obj.get("metadata", {}))
                )
        store._id_to_row = {c.id: i for i, c in enumerate(store._chunks)}
        return store


# ---- helpers ----


def _l2_normalize(mat: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


def _matches(metadata: dict[str, Any], filters: dict[str, Any]) -> bool:
    for key, expected in filters.items():
        actual = metadata.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif key == "time_range":
            # expected: {"start": iso, "end": iso}
            ts = metadata.get("timestamp")
            if not ts:
                return False
            if expected.get("start") and ts < expected["start"]:
                return False
            if expected.get("end") and ts > expected["end"]:
                return False
        elif key == "time_after":
            ts = metadata.get("timestamp")
            if not ts or ts < expected:
                return False
        elif key == "time_before":
            ts = metadata.get("timestamp")
            if not ts or ts > expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def _chunk_to_jsonl(self: Chunk) -> str:
    return json.dumps(
        {"id": self.id, "text": self.text, "metadata": self.metadata},
        ensure_ascii=False,
    )


Chunk.to_jsonl = _chunk_to_jsonl  # type: ignore[attr-defined]