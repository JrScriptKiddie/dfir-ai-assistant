"""Tests for hayabusa CSV parser and chunker."""

import csv
from pathlib import Path

from src.pipeline.hayabusa import parse_hayabusa_csv, hayabusa_events_to_chunks


def _write_test_csv(path: Path) -> None:
    """Write a minimal hayabusa-like CSV for testing."""
    rows = [
        {
            "Timestamp": "2021-04-19T07:39:33+00:00",
            "RuleTitle": "Suspicious Service Created",
            "RuleFile": "sigma/service_creation.yml",
            "Severity": "high",
            "EventID": "7045",
            "Channel": "Security",
            "Computer": "SRV.nebo.ru",
            "SubjectUserName": "adm_pavel",
            "SubjectDomainName": "NEBO",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "ProcessName": "-",
            "MitreTactics": "Persistence, Privilege Escalation",
            "MitreTags": "T1543.003",
        },
        {
            "Timestamp": "2021-04-19T07:54:21+00:00",
            "RuleTitle": "Network Reconnaissance",
            "RuleFile": "sigma/net_recon.yml",
            "Severity": "medium",
            "EventID": "7045",
            "Channel": "Security",
            "Computer": "SRV.nebo.ru",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "ProcessName": "-",
            "MitreTactics": "Discovery",
            "MitreTags": "T1016",
        },
    ]
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_parse_hayabusa_csv(tmp_path):
    csv_path = tmp_path / "alerts.csv"
    _write_test_csv(csv_path)
    events = parse_hayabusa_csv(csv_path, "test-case")
    assert len(events) == 2
    assert events[0]["source"] == "SIGMA"
    assert events[0]["event_id"] == "7045"
    assert events[0]["severity"] == "high"
    assert "T1543.003" in events[0]["mitre_tags"]
    assert "Suspicious Service Created" in events[0]["message"]
    assert events[0]["case_id"] == "test-case"


def test_hayabusa_events_to_chunks():
    events = [
        {
            "case_id": "test",
            "timestamp": "2021-04-19T07:39:33+00:00",
            "source": "SIGMA",
            "sourcetype": "Hayabusa/high",
            "event_id": "7045",
            "parser": "hayabusa",
            "host": "SRV.nebo.ru",
            "user": "adm_pavel",
            "message": "[SIGMA] Suspicious Service Created | severity=high | EID=7045",
            "mitre_tactics": "Persistence",
            "mitre_tags": "T1543.003",
            "rule_title": "Suspicious Service Created",
            "severity": "high",
        },
    ]
    chunks = hayabusa_events_to_chunks(events, "test")
    assert len(chunks) == 1
    assert chunks[0].metadata["source"] == "SIGMA"
    assert chunks[0].metadata["severity"] == "high"
    assert chunks[0].metadata["mitre_tags"] == "T1543.003"
    assert "Suspicious Service Created" in chunks[0].text


def test_hayabusa_chunk_deterministic_id():
    events = [
        {
            "case_id": "c1",
            "timestamp": "2021-04-19T07:39:33+00:00",
            "source": "SIGMA",
            "message": "[SIGMA] Test Rule",
            "rule_title": "Test Rule",
            "severity": "high",
        },
    ]
    c1 = hayabusa_events_to_chunks(events, "c1")
    c2 = hayabusa_events_to_chunks(events, "c1")
    assert c1[0].id == c2[0].id
    # different case -> different id
    c3 = hayabusa_events_to_chunks(events, "c2")
    assert c1[0].id != c3[0].id