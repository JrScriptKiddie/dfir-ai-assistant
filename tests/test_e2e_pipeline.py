"""End-to-end pipeline test: normalize -> chunk -> embed -> turboVEC -> query.

Uses synthetic plaso-like events and DummyEmbedder (no external deps).
"""

import json

from src.rag.embedder import DummyEmbedder
from src.rag.indexer import build_index_from_events, query_store
from src.pipeline.normalizer import normalize_file


_SYNTHETIC_TIMELINE = [
    # login events
    {"datetime": "2024-03-12T08:14:22+00:00", "source_short": "EVTX",
     "source_long": "Security", "message": "Logon Event ID: 4624 user jsmith type 3 from WS01",
     "parser": "winevtx", "data_type": "windows:evtx:record",
     "hostname": "DC01", "username": "jsmith"},
    {"datetime": "2024-03-12T08:15:00+00:00", "source_short": "EVTX",
     "source_long": "Security", "message": "Logon Event ID: 4624 user admin type 10 from 10.0.0.5",
     "parser": "winevtx", "data_type": "windows:evtx:record",
     "hostname": "DC01", "username": "admin"},
    # process creation
    {"datetime": "2024-03-12T08:20:00+00:00", "source_short": "EVTX",
     "source_long": "Security", "message": "Process created Event ID: 4688 powershell.exe -enc abc123",
     "parser": "winevtx", "data_type": "windows:evtx:record",
     "hostname": "WS01", "username": "jsmith"},
    # prefetch
    {"datetime": "2024-03-12T08:20:05+00:00", "source_short": "FILE",
     "source_long": "Prefetch", "message": "Prefetch: POWERSHELL.EXE run count 1",
     "parser": "winprefetch", "data_type": "windows:prefetch",
     "hostname": "WS01", "username": ""},
    # lateral
    {"datetime": "2024-03-12T09:00:00+00:00", "source_short": "EVTX",
     "source_long": "Security", "message": "Logon Event ID: 4624 user jsmith type 3 from WS01 to DC02",
     "parser": "winevtx", "data_type": "windows:evtx:record",
     "hostname": "DC02", "username": "jsmith"},
]


def _write_timeline(tmp_path):
    p = tmp_path / "timeline.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in _SYNTHETIC_TIMELINE), encoding="utf-8")
    return p


def test_end_to_end_pipeline(tmp_path):
    # 1. normalize
    timeline = _write_timeline(tmp_path)
    events = tmp_path / "events.jsonl"
    stats = normalize_file(timeline, events, "case-synth")
    assert stats["output_events"] == 5

    # 2. chunk + embed + index
    out_dir = tmp_path / "turbovec"
    embedder = DummyEmbedder(dim=256)
    store = build_index_from_events(events, "case-synth", out_dir, embedder)
    assert store.stats()["n_vectors"] == 5

    # 3. query
    hits = query_store(store, embedder, "powershell execution", k=3)
    assert len(hits) > 0
    # at least one hit should mention powershell
    texts = [h.chunk.text.lower() for h in hits]
    assert any("powershell" in t for t in texts)

    # 4. filter by host
    hits_dc = query_store(
        store, embedder, "logon", k=5, filters={"host": "DC01"}
    )
    assert all(h.chunk.metadata["host"] == "DC01" for h in hits_dc)
    assert len(hits_dc) == 2

    # 5. persistence
    store.save(out_dir)
    from src.rag.turbovec import TurboVec
    loaded = TurboVec.load(out_dir)
    assert loaded.stats()["n_vectors"] == 5
    hits2 = query_store(loaded, embedder, "powershell execution", k=3)
    assert len(hits2) == len(hits)