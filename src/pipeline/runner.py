"""Pipeline runner: orchestrates plaso Docker -> normalize -> chunk -> index.

Usage:
    python -m src.pipeline.runner <case_id> [--evidence-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from ..rag.embedder import get_embedder
from ..rag.indexer import build_index_from_events
from .normalizer import normalize_file

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"


def run_plaso_container(case_id: str, evidence_dir: Path, output_dir: Path) -> int:
    """Run plaso in Docker. Returns exit code."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{evidence_dir}:/evidence:ro",
        "-v", f"{output_dir}:/output",
        "-e", f"PLASO_PARSERS={os.environ.get('PLASO_PARSERS', 'winevtx,winreg,prefetch,filestat')}",
        "-e", f"PLASO_VSS={os.environ.get('PLASO_VSS', 'none')}",
        "dfir-plaso",
        case_id,
    ]
    print(f"[runner] docker: {' '.join(cmd)}")
    return subprocess.call(cmd)


def run_pipeline(case_id: str, evidence_dir: Path | None = None) -> dict:
    """Full pipeline: plaso -> normalize -> chunk -> index."""
    triage_dir = evidence_dir or (DATA_DIR / "triage" / case_id)
    timeline_dir = DATA_DIR / "timelines" / case_id
    processed_dir = DATA_DIR / "processed" / case_id

    stats: dict = {"case_id": case_id, "steps": []}

    # 1. plaso
    timeline_jsonl = timeline_dir / f"{case_id}.timeline.jsonl"
    if not timeline_jsonl.exists():
        rc = run_plaso_container(case_id, triage_dir, timeline_dir)
        if rc != 0:
            stats["status"] = "failed"
            stats["error"] = f"plaso exited with {rc}"
            return stats
    stats["steps"].append("plaso")

    # 2. normalize
    events_path = processed_dir / "events.jsonl"
    norm_stats = normalize_file(timeline_jsonl, events_path, case_id)
    stats["normalize"] = norm_stats
    stats["steps"].append("normalize")

    # 3. chunk + index
    turbovec_dir = processed_dir / "turbovec"
    embedder = get_embedder()
    store = build_index_from_events(events_path, case_id, turbovec_dir, embedder)
    stats["index"] = store.stats()
    stats["status"] = "ready"
    stats["steps"].append("index")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="DFIR pipeline runner")
    ap.add_argument("case_id", help="case identifier")
    ap.add_argument("--evidence-dir", type=Path, default=None, help="override evidence path")
    args = ap.parse_args()
    stats = run_pipeline(args.case_id, args.evidence_dir)
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    return 0 if stats.get("status") == "ready" else 1


if __name__ == "__main__":
    sys.exit(main())