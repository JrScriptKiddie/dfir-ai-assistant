"""Tests for chunker: events -> chunks."""

import json

from src.rag.chunker import chunk_events_file, event_to_chunk, write_chunks


def test_event_to_chunk():
    event = {
        "case_id": "case1",
        "timestamp": "2024-03-12T08:14:22Z",
        "source": "EVTX",
        "sourcetype": "Security",
        "event_id": "4624",
        "parser": "winevtx",
        "host": "DC01",
        "user": "jsmith",
        "message": "Logon successful",
    }
    chunk = event_to_chunk(event, "case1")
    assert chunk.id  # non-empty
    assert len(chunk.id) == 16
    assert "2024-03-12T08:14:22Z" in chunk.text
    assert "EVTX" in chunk.text
    assert "Logon successful" in chunk.text
    assert chunk.metadata["host"] == "DC01"
    assert chunk.metadata["case_id"] == "case1"


def test_chunk_events_file(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "source": "EVTX", "message": "login"},
        {"timestamp": "2024-01-01T00:01:00Z", "source": "EVTX", "message": "logout"},
        {"timestamp": "2024-01-01T00:02:00Z", "source": "EVTX", "message": ""},  # skipped
    ]
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    chunks = chunk_events_file(p, "case1")
    assert len(chunks) == 2  # empty message skipped
    assert all(c.metadata["case_id"] == "case1" for c in chunks)


def test_deterministic_id():
    event = {
        "timestamp": "2024-01-01T00:00:00Z",
        "source": "EVTX",
        "message": "login",
    }
    c1 = event_to_chunk(event, "case1")
    c2 = event_to_chunk(event, "case1")
    assert c1.id == c2.id
    # different case -> different id
    c3 = event_to_chunk(event, "case2")
    assert c1.id != c3.id


def test_write_chunks(tmp_path):
    from src.rag.turbovec import Chunk

    chunks = [Chunk(id="a", text="foo", metadata={"x": 1})]
    out = tmp_path / "chunks.jsonl"
    write_chunks(chunks, out)
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["id"] == "a"
    assert obj["text"] == "foo"