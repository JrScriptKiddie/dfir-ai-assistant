"""TF-IDF embedder: lightweight semantic-ish embeddings using only numpy.

Builds a vocabulary from all texts, computes TF-IDF vectors.
Better than hash-based for keyword matching (logon, powershell, encrypt).
No external dependencies beyond numpy.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import numpy as np


class TfidfEmbedder:
    """TF-IDF embedder with char-level n-gram fallback.

    Fits vocabulary on first embed() call, then reuses.
    Supports incremental vocab expansion.
    """

    def __init__(self, dim: int = 256, ngram: int = 3) -> None:
        self._dim = dim
        self._ngram = ngram
        self._vocab: dict[str, int] = {}
        self._idf: np.ndarray | None = None
        self._fitted = False

    @property
    def dim(self) -> int:
        return self._dim

    def _tokenize(self, text: str) -> list[str]:
        """Word tokens + char n-grams for robustness."""
        text = text.lower()
        words = re.findall(r"[a-z0-9_]+", text)
        tokens = list(words)
        # add char n-grams for partial matching
        for w in words:
            padded = f"#{w}#"
            for i in range(len(padded) - self._ngram + 1):
                tokens.append(padded[i : i + self._ngram])
        return tokens

    def _ensure_vocab(self, texts: list[str]) -> None:
        if self._fitted and self._idf is not None:
            # vocab is frozen after initial fit - do not expand
            return

        # initial fit
        df: Counter[str] = Counter()
        for t in texts:
            tokens = set(self._tokenize(t))
            for tok in tokens:
                df[tok] += 1
        # select top dim tokens by document frequency
        top = df.most_common(self._dim)
        self._vocab = {tok: i for i, (tok, _) in enumerate(top)}
        n_docs = len(texts)
        self._idf = np.zeros(len(self._vocab), dtype=np.float32)
        for tok, idx in self._vocab.items():
            self._idf[idx] = np.log((n_docs + 1) / (df[tok] + 1)) + 1
        self._fitted = True

    def _recompute_idf(self, texts: list[str]) -> None:
        """Recompute IDF with expanded vocab (approximate)."""
        if self._idf is None:
            return
        # keep existing IDF, set new tokens to max IDF (rare = high weight)
        new_size = len(self._vocab)
        if new_size > len(self._idf):
            new_idf = np.ones(new_size, dtype=np.float32) * float(np.max(self._idf))
            new_idf[: len(self._idf)] = self._idf
            self._idf = new_idf

    def embed(self, texts: list[str]) -> np.ndarray:
        self._ensure_vocab(texts)
        n = len(texts)
        vecs = np.zeros((n, len(self._vocab)), dtype=np.float32)
        for i, text in enumerate(texts):
            tokens = self._tokenize(text)
            tf = Counter(tokens)
            for tok, count in tf.items():
                idx = self._vocab.get(tok)
                if idx is not None and self._idf is not None:
                    vecs[i, idx] = count * self._idf[idx]
        # L2 normalize
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vecs / norms

    def fit(self, texts: list[str]) -> "TfidfEmbedder":
        """Pre-fit vocabulary on a corpus."""
        self._ensure_vocab(texts)
        return self

    def save(self, path: str | Path) -> None:
        """Save vocab and idf to a .npz file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        vocab_items = np.array(
            list(self._vocab.items()), dtype=object
        )
        np.savez(
            p,
            vocab_keys=vocab_items[:, 0],
            vocab_vals=vocab_items[:, 1].astype(np.int32),
            idf=self._idf,
            dim=self._dim,
            ngram=self._ngram,
        )

    @classmethod
    def load(cls, path: str | Path) -> "TfidfEmbedder":
        """Load a pre-fit embedder from a .npz file."""
        p = Path(path)
        data = np.load(p, allow_pickle=True)
        emb = cls(dim=int(data["dim"]), ngram=int(data["ngram"]))
        keys = data["vocab_keys"]
        vals = data["vocab_vals"]
        emb._vocab = {str(k): int(v) for k, v in zip(keys, vals)}
        emb._idf = data["idf"]
        emb._fitted = True
        return emb