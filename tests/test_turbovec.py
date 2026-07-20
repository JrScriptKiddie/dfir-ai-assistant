"""Tests for turboVEC vector store."""

import numpy as np

from src.rag.turbovec import Chunk, TurboVec


def _make_chunk(i: int) -> Chunk:
    return Chunk(id=f"c{i}", text=f"event {i}", metadata={"event_id": str(i)})


def test_add_and_query():
    store = TurboVec(dim=4, case_id="test")
    chunks = [_make_chunk(i) for i in range(3)]
    # orthogonal-ish vectors
    vecs = np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0]], dtype=np.float32)
    store.add(chunks, vecs)
    assert store.stats()["n_vectors"] == 3

    # query with [1,0,0,0] should return c0 first
    hits = store.query(np.array([1, 0, 0, 0], dtype=np.float32), k=3)
    assert len(hits) == 3
    assert hits[0].chunk.id == "c0"
    assert hits[0].score > 0.99


def test_filters():
    store = TurboVec(dim=4)
    chunks = [
        Chunk(id="a", text="a", metadata={"host": "DC01", "event_id": "4624"}),
        Chunk(id="b", text="b", metadata={"host": "WS01", "event_id": "4688"}),
    ]
    vecs = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)
    store.add(chunks, vecs)
    hits = store.query(np.array([1, 1, 0, 0], dtype=np.float32), k=2, filters={"host": "DC01"})
    assert len(hits) == 1
    assert hits[0].chunk.id == "a"


def test_persistence(tmp_path):
    store = TurboVec(dim=4, case_id="case1", embedding_model="dummy")
    chunks = [_make_chunk(i) for i in range(2)]
    vecs = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)
    store.add(chunks, vecs)
    p = tmp_path / "tv"
    store.save(p)
    assert (p / "vectors.npy").exists()
    assert (p / "meta.jsonl").exists()
    assert (p / "index.json").exists()

    loaded = TurboVec.load(p)
    assert loaded.stats()["n_vectors"] == 2
    assert loaded.stats()["case_id"] == "case1"
    hits = loaded.query(np.array([1, 0, 0, 0], dtype=np.float32), k=2)
    assert hits[0].chunk.id == "c0"


def test_replace_existing():
    store = TurboVec(dim=4)
    c1 = Chunk(id="x", text="old", metadata={"v": 1})
    store.add([c1], np.array([[1, 0, 0, 0]], dtype=np.float32))
    # same id, new content
    c2 = Chunk(id="x", text="new", metadata={"v": 2})
    store.add([c2], np.array([[0, 1, 0, 0]], dtype=np.float32))
    assert store.stats()["n_vectors"] == 1  # not 2
    got = store.get("x")
    assert got is not None
    assert got.text == "new"