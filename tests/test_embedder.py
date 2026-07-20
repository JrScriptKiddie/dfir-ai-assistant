"""Tests for embedder: dummy backend produces stable vectors."""

import numpy as np

from src.rag.embedder import DummyEmbedder, get_embedder


def test_dummy_embedder_stable():
    emb = DummyEmbedder(dim=128)
    texts = ["hello world", "foo bar baz"]
    v1 = emb.embed(texts)
    v2 = emb.embed(texts)
    assert v1.shape == (2, 128)
    np.testing.assert_array_equal(v1, v2)


def test_dummy_embedder_different_texts():
    emb = DummyEmbedder(dim=64)
    v = emb.embed(["aaa", "bbb"])
    assert not np.array_equal(v[0], v[1])


def test_get_embedder_dummy():
    e = get_embedder("dummy", dim=32)
    assert isinstance(e, DummyEmbedder)
    assert e.dim == 32