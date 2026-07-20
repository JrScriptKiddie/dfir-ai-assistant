"""Chunker: 1 timeline event = 1 RAG chunk.

Reads normalized events.jsonl, produces chunks.jsonl.
Each chunk has deterministic id = sha1(case_id|timestamp|source|message).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .turbovec import Chunk


def event_to_chunk(event: dict, case_id: str) -> Chunk:
    """Convert one normalized event dict to a Chunk."""
    timestamp = event.get("timestamp", "")
    source = event.get("source", "")
    sourcetype = event.get("sourcetype", "")
    message = event.get("message", "")
    host = event.get("host", "")
    user = event.get("user", "")
    event_id = event.get("event_id", "")
    parser = event.get("parser", "")

    # human-readable text for embedding
    text_parts = [
        f"{timestamp} | {source}",
        f"{sourcetype}" + (f" | {event_id}" if event_id else ""),
        message,
    ]
    if host:
        text_parts.append(f"host={host}")
    if user:
        text_parts.append(f"user={user}")
    text = " | ".join(text_parts)

    # deterministic id
    raw = f"{case_id}|{timestamp}|{source}|{message}"
    chunk_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    metadata = {
        "case_id": case_id,
        "timestamp": timestamp,
        "source": source,
        "sourcetype": sourcetype,
        "event_id": event_id,
        "parser": parser,
        "host": host,
        "user": user,
    }
    # include extra fields from event
    for k, v in event.items():
        if k not in metadata and k != "message":
            metadata[k] = v

    return Chunk(id=chunk_id, text=text, metadata=metadata)


def chunk_events_file(events_path: str | Path, case_id: str) -> list[Chunk]:
    """Read events.jsonl, return list of Chunks."""
    chunks: list[Chunk] = []
    with open(events_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if not event.get("message"):
                continue
            chunks.append(event_to_chunk(event, case_id))
    return chunks


def write_chunks(chunks: list[Chunk], out_path: str | Path) -> None:
    """Write chunks to JSONL."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(chunk.to_jsonl() + "\n")