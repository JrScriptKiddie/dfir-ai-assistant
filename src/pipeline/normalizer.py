"""Normalizer: plaso json_line output -> normalized events.jsonl.

Plaso json_line schema (2024+):
  timestamp: int microseconds (0 = "Not a time")
  timestamp_desc: human description
  data_type: e.g. "windows:evtx:record", "windows:registry:key_value"
  message: human-readable event text
  parser: e.g. "winevtx", "winreg/userassist"
  hostname, username: optional
  event_identifier: for EVTX
  display_name: source file path
  date_time: structured (may be NotSet)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _timestamp_to_iso(ts: int) -> str:
    """plaso timestamp (microseconds since 1970-01-01) -> ISO string."""
    if not ts or ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts / 1_000_000, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


def _extract_event_id(message: str, data_type: str) -> str:
    """Try to extract Windows Event ID from message or data_type."""
    if "evtx" in data_type:
        # plaso message format: "[7036 / 0x1b7c] Provider identifier: ..."
        m = re.match(r"\[(\d+)", message)
        if m:
            return m.group(1)
    return ""


def _classify_source(data_type: str, parser: str) -> tuple[str, str]:
    """Return (source_short, source_long) from data_type/parser."""
    if "evtx" in data_type:
        return "EVTX", "WinEVTX"
    if "registry" in data_type or "winreg" in parser:
        return "REG", "Windows Registry"
    if "prefetch" in data_type or "prefetch" in parser:
        return "FILE", "Prefetch"
    if "fs:" in data_type or "filestat" in parser:
        return "FILE", "Filesystem"
    if "amcache" in data_type:
        return "REG", "Amcache"
    if "userassist" in data_type:
        return "REG", "UserAssist"
    if "task_scheduler" in data_type:
        return "TASK", "Task Scheduler"
    return "MISC", data_type


def normalize_event(raw: dict, case_id: str) -> dict | None:
    """Convert one plaso json_line dict to normalized event dict."""
    message = (raw.get("message") or "").strip()
    if not message:
        return None
    # skip "Not a time" entries (timestamp=0)
    ts = raw.get("timestamp", 0)
    timestamp = _timestamp_to_iso(ts) if ts else ""
    # skip events without a real timestamp? keep them but mark
    data_type = raw.get("data_type", "")
    parser = raw.get("parser", "")
    source_short, source_long = _classify_source(data_type, parser)
    event_id = _extract_event_id(message, data_type)
    # prefer explicit event_identifier field
    if not event_id and raw.get("event_identifier"):
        event_id = str(raw["event_identifier"])
    host = raw.get("hostname", "") or _extract_host(raw.get("display_name", ""))
    user = raw.get("username", "")

    return {
        "case_id": case_id,
        "timestamp": timestamp,
        "timestamp_desc": raw.get("timestamp_desc", ""),
        "source": source_short,
        "sourcetype": source_long,
        "event_id": str(event_id) if event_id else "",
        "parser": parser,
        "data_type": data_type,
        "host": host,
        "user": user,
        "message": message,
        "display_name": raw.get("display_name", ""),
    }


def _extract_host(display_name: str) -> str:
    """Try to extract hostname from evtx display_name path."""
    if not display_name:
        return ""
    # e.g. "OS:.../winevt/Logs/System.evtx" -> "System" is log, not host
    # We don't have host in display_name for loose files
    return ""


def _dedup_key(event: dict) -> str:
    return f"{event['timestamp']}|{event['source']}|{event['sourcetype']}|{event['message']}"


def normalize_file(in_path: str | Path, out_path: str | Path, case_id: str) -> dict:
    """Normalize plaso json_line to events.jsonl. Returns stats dict."""
    seen: set[str] = set()
    n_in = 0
    n_out = 0
    n_skipped = 0
    n_dup = 0
    n_no_time = 0

    out_p = Path(out_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    with open(in_path, encoding="utf-8") as fin, open(out_p, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                n_skipped += 1
                continue
            event = normalize_event(raw, case_id)
            if event is None:
                n_skipped += 1
                continue
            if not event["timestamp"]:
                n_no_time += 1
                # keep events without timestamp (they may still be useful)
            key = _dedup_key(event)
            if key in seen:
                n_dup += 1
                continue
            seen.add(key)
            fout.write(json.dumps(event, ensure_ascii=False) + "\n")
            n_out += 1

    return {
        "input_events": n_in,
        "output_events": n_out,
        "duplicates": n_dup,
        "skipped": n_skipped,
        "no_timestamp": n_no_time,
        "case_id": case_id,
    }