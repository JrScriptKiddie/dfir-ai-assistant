"""RAG: combines embedder + turboVEC for retrieval."""

from __future__ import annotations

from pathlib import Path

from .chunker import chunk_events_file
from .embedder import Embedder, get_embedder
from .turbovec import Hit, TurboVec


def build_index_from_events(
    events_path: str | Path,
    case_id: str,
    out_dir: str | Path,
    embedder: Embedder | None = None,
) -> TurboVec:
    """Full pipeline: events.jsonl -> chunks -> embeddings -> turboVEC save."""
    if embedder is None:
        embedder = get_embedder()
    chunks = chunk_events_file(events_path, case_id)
    if not chunks:
        raise ValueError(f"no chunks produced from {events_path}")
    texts = [c.text for c in chunks]
    # pre-fit TF-IDF vocabulary on the corpus if applicable
    if hasattr(embedder, "fit"):
        embedder.fit(texts)
    embeddings = embedder.embed(texts)
    store = TurboVec(
        dim=embeddings.shape[1],
        case_id=case_id,
        embedding_model=getattr(embedder, "model", embedder.__class__.__name__),
    )
    store.add(chunks, embeddings)
    store.save(out_dir)
    # save TF-IDF embedder state if applicable
    if hasattr(embedder, "save"):
        embedder.save(Path(out_dir) / "embedder.npz")
    return store


def load_index(index_dir: str | Path) -> TurboVec:
    return TurboVec.load(index_dir)


def query_store(
    store: TurboVec,
    embedder: Embedder,
    text: str,
    k: int = 10,
    filters: dict | None = None,
) -> list[Hit]:
    q = embedder.embed([text])
    return store.query(q[0], k=k, filters=filters)