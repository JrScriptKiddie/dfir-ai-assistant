"""Hayabusa integration: Sigma rule matching on Windows Event Logs.

Hayabusa (https://github.com/Yamato-Security/hayabusa) is a fast,
thread-based Windows Event Log analyzer that uses Sigma rules to
detect suspicious activity in EVTX files.

Integration plan:
  1. Run hayabusa on EVTX files from triage -> CSV alerts
  2. Parse alerts -> normalized events -> add to RAG timeline
  3. Hayabusa subagent queries RAG for sigma alerts
  4. Sigma alerts provide pre-built TTP mapping (MITRE ATT&CK tags)

Benefits over pure LLM analysis:
  - Sigma rules are community-maintained, battle-tested detections
  - No hallucination: rule match = deterministic detection
  - Hayabusa covers 3000+ rules from Sigma+EXCEPTOR+rules hayabusa
  - MITRE ATT&CK tags included in rule metadata
  - Complements LLM: hayabusa finds known patterns, LLM correlates

Pipeline:
```
[EVTX files from triage]
       |
       v
[hayabusa csv-timeline -d]  -> alerts.csv
       |
       v
[Parser: alerts.csv -> normalized events]
       |
       v
[Add to RAG timeline (as separate source="SIGMA")]
       |
       v
[Hayabusa subagent queries RAG for sigma alerts]
       |
       v
[Sigma alerts report with MITRE ATT&CK mapping]
```

Hayabusa command:
  hayabusa csv-timeline -d <evtx_dir> -o alerts.csv -p super-verbose
  # -d: directory with EVTX files
  # -o: output CSV
  # -p super-verbose: includes all fields including MITRE ATT&CK

Hayabusa CSV columns (super-verbose):
  Timestamp, RuleTitle, RuleFile, Severity, EventID, Channel,
  Computer, SubjectUserName, SubjectDomainName, TargetUserName,
  TargetDomainName, ProcessName, ... , MitreTactics, MitreTags

Docker integration:
  docker run --rm -v <evtx_dir>:/evtx -v <output_dir>:/output \
    yamatosecurity/hayabusa csv-timeline -d /evtx -o /output/alerts.csv -p super-verbose
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..rag.turbovec import Chunk


def parse_hayabusa_csv(csv_path: str | Path, case_id: str) -> list[dict]:
    """Parse hayabusa CSV output -> normalized events.

    Returns list of event dicts compatible with our normalizer format.
    """
    events: list[dict] = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            timestamp = row.get("Timestamp", "")
            rule_title = row.get("RuleTitle", "")
            severity = row.get("Severity", "")
            event_id = row.get("EventID", "")
            channel = row.get("Channel", "")
            computer = row.get("Computer", "")
            mitre_tactics = row.get("MitreTactics", "")
            mitre_tags = row.get("MitreTags", "")
            rule_file = row.get("RuleFile", "")

            # build message from key fields
            msg_parts = [f"[SIGMA] {rule_title}"]
            if severity:
                msg_parts.append(f"severity={severity}")
            if event_id:
                msg_parts.append(f"EID={event_id}")
            if channel:
                msg_parts.append(f"channel={channel}")
            if mitre_tactics:
                msg_parts.append(f"MITRE={mitre_tactics}")
            if mitre_tags:
                msg_parts.append(f"tags={mitre_tags}")
            if rule_file:
                msg_parts.append(f"rule={rule_file}")

            # extract user/computer fields
            for field_name in ["SubjectUserName", "TargetUserName", "SourceIp"]:
                val = row.get(field_name, "")
                if val and val != "-":
                    msg_parts.append(f"{field_name}={val}")

            message = " | ".join(msg_parts)

            events.append({
                "case_id": case_id,
                "timestamp": timestamp,
                "timestamp_desc": "Sigma Rule Match",
                "source": "SIGMA",
                "sourcetype": f"Hayabusa/{severity}",
                "event_id": str(event_id) if event_id else "",
                "parser": "hayabusa",
                "data_type": "sigma:rule:match",
                "host": computer,
                "user": row.get("SubjectUserName", "") or row.get("TargetUserName", ""),
                "message": message,
                "mitre_tactics": mitre_tactics,
                "mitre_tags": mitre_tags,
                "rule_title": rule_title,
                "severity": severity,
            })
    return events


def hayabusa_events_to_chunks(events: list[dict], case_id: str) -> list[Chunk]:
    """Convert hayabusa events to RAG chunks."""
    import hashlib

    chunks: list[Chunk] = []
    for event in events:
        message = event.get("message", "")
        if not message:
            continue
        timestamp = event.get("timestamp", "")
        source = event.get("source", "SIGMA")
        rule_title = event.get("rule_title", "")
        severity = event.get("severity", "")

        text = f"{timestamp} | {source} | {severity} | {rule_title} | {message}"

        raw = f"{case_id}|{timestamp}|{rule_title}|{message}"
        chunk_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

        metadata = {
            "case_id": case_id,
            "timestamp": timestamp,
            "source": source,
            "sourcetype": event.get("sourcetype", ""),
            "event_id": event.get("event_id", ""),
            "parser": "hayabusa",
            "host": event.get("host", ""),
            "user": event.get("user", ""),
            "severity": severity,
            "mitre_tactics": event.get("mitre_tactics", ""),
            "mitre_tags": event.get("mitre_tags", ""),
            "rule_title": rule_title,
        }
        chunks.append(Chunk(id=chunk_id, text=text, metadata=metadata))
    return chunks


def run_hayabusa_docker(evtx_dir: str | Path, output_csv: str | Path) -> int:
    """Run hayabusa in Docker on EVTX files.

    Returns exit code. Requires Docker access.
    """
    import subprocess

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{evtx_dir}:/evtx:ro",
        "-v", f"{Path(output_csv).parent}:/output",
        "yamatosecurity/hayabusa",
        "csv-timeline", "-d", "/evtx",
        "-o", f"/output/{Path(output_csv).name}",
        "-p", "super-verbose",
    ]
    return subprocess.call(cmd)