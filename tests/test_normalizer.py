"""Tests for normalizer: plaso json_line -> events.jsonl."""

import json

from src.pipeline.normalizer import normalize_file, normalize_event


def test_normalize_event_evtx():
    raw = {
        "timestamp": 1416633231843062,
        "timestamp_desc": "Content Modification Time",
        "data_type": "windows:evtx:record",
        "message": "[7036 / 0x1b7c] Provider identifier: {555} Source Name: Service Control Manager Computer Name: WIN-VMS19PN1AND Record Number: 1 Event Level: 4",
        "parser": "winevtx",
        "hostname": "WIN-VMS19PN1AND",
        "event_identifier": 7036,
        "display_name": "OS:.../winevt/Logs/System.evtx",
    }
    event = normalize_event(raw, "case1")
    assert event is not None
    assert event["event_id"] == "7036"
    assert event["source"] == "EVTX"
    assert event["sourcetype"] == "WinEVTX"
    assert event["host"] == "WIN-VMS19PN1AND"
    assert event["case_id"] == "case1"
    assert event["timestamp"].startswith("2014")  # 1416633231 -> Nov 2014


def test_normalize_event_registry():
    raw = {
        "timestamp": 1320000000000000,
        "timestamp_desc": "Content Modification Time",
        "data_type": "windows:registry:key_value",
        "message": "[HKLM\\Software\\Foo] Value: bar Type: SZ",
        "parser": "winreg/default",
        "display_name": "OS:.../config/SOFTWARE",
    }
    event = normalize_event(raw, "case1")
    assert event is not None
    assert event["source"] == "REG"
    assert event["sourcetype"] == "Windows Registry"
    assert event["event_id"] == ""


def test_normalize_event_empty_message():
    raw = {"timestamp": 1000, "data_type": "fs:stat", "message": ""}
    assert normalize_event(raw, "c1") is None


def test_normalize_event_no_timestamp():
    raw = {
        "timestamp": 0,
        "timestamp_desc": "Not a time",
        "data_type": "windows:registry:userassist",
        "message": "UserAssist entry: Count: 0",
        "parser": "winreg/userassist",
    }
    event = normalize_event(raw, "c1")
    assert event is not None
    assert event["timestamp"] == ""
    assert event["source"] == "REG"


def test_normalize_file_dedup(tmp_path):
    events = [
        {"timestamp": 1609459200000000, "timestamp_desc": "CMT",
         "data_type": "windows:evtx:record", "message": "login",
         "parser": "winevtx"},
        {"timestamp": 1609459200000000, "timestamp_desc": "CMT",
         "data_type": "windows:evtx:record", "message": "login",
         "parser": "winevtx"},
        {"timestamp": 1609459260000000, "timestamp_desc": "CMT",
         "data_type": "windows:evtx:record", "message": "logout",
         "parser": "winevtx"},
    ]
    in_p = tmp_path / "timeline.jsonl"
    in_p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    out_p = tmp_path / "events.jsonl"
    stats = normalize_file(in_p, out_p, "case1")
    assert stats["input_events"] == 3
    assert stats["output_events"] == 2
    assert stats["duplicates"] == 1
    lines = out_p.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2