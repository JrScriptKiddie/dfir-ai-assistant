"""CLI for DFIR Agent.

Two modes:
  1. Incident investigation (with --incident description):
     python -m src.agents.cli incident --case <id> --incident "files encrypted"

  2. Compromise assessment (autonomous, no description):
     python -m src.agents.cli assess --case <id>

Environment:
  OLLAMA_HOST=https://ollama.com/v1
  OLLAMA_API_KEY=...
  OLLAMA_MODEL=glm-5.2
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..rag.embedder import get_embedder
from ..rag.turbovec import TurboVec
from .dfir_agent import DFIRAgent
from .llm import get_llm

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"


def _load_agent(args: argparse.Namespace) -> DFIRAgent:
    case_id = args.case_id
    index_dir = Path(args.index_dir or DATA_DIR / "processed" / case_id / "turbovec")

    if not index_dir.exists():
        print(f"[error] turboVEC index not found: {index_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[agent] loading turboVEC from {index_dir}")
    store = TurboVec.load(index_dir)
    print(f"[agent] index: {store.stats()['n_vectors']} vectors, dim={store.stats()['dim']}")

    embedder_npz = index_dir / "embedder.npz"
    if embedder_npz.exists() and (args.embedder in (None, "tfidf")):
        from ..rag.tfidf_embedder import TfidfEmbedder
        embedder = TfidfEmbedder.load(embedder_npz)
        print(f"[agent] loaded TF-IDF embedder from {embedder_npz}")
    else:
        embedder = get_embedder(args.embedder)

    llm = get_llm(args.llm_backend)
    print(f"[agent] LLM: {llm.__class__.__name__} model={llm.model}")
    print(f"[agent] embedder: {embedder.__class__.__name__} dim={embedder.dim}")

    return DFIRAgent(store=store, embedder=embedder, llm=llm, k=args.k)


def _save_report(report: str, case_id: str, mode: str) -> Path:
    report_path = DATA_DIR / "processed" / case_id / f"report_{mode}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report_path


def cmd_incident(args: argparse.Namespace) -> int:
    agent = _load_agent(args)
    print("[agent] mode: INCIDENT")
    print(f"[agent] incident: {args.incident}")
    print("[agent] retrieving and analyzing...")

    result = agent.run_incident(args.incident)

    report_path = _save_report(result.report, args.case_id, "incident")
    print(f"[agent] report saved: {report_path}")
    print(f"[agent] hits used: {len(result.hits_used)}")

    print("\n" + "=" * 70)
    print("INCIDENT REPORT")
    print("=" * 70)
    print(result.report)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    agent = _load_agent(args)
    print("[agent] mode: COMPROMISE ASSESSMENT")
    print("[agent] autonomous exploration - no incident description given")
    print("[agent] retrieving and analyzing...")

    result = agent.run_assessment()

    report_path = _save_report(result.report, args.case_id, "assessment")
    print(f"[agent] report saved: {report_path}")
    print(f"[agent] hits used: {len(result.hits_used)}")

    print("\n" + "=" * 70)
    print("COMPROMISE ASSESSMENT")
    print("=" * 70)
    print(result.report)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="DFIR AI Assistant CLI")
    sub = ap.add_subparsers(dest="command", required=True)

    # shared args
    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--case", dest="case_id", required=True, help="case identifier")
        p.add_argument("--index-dir", default=None, help="override turboVEC path")
        p.add_argument("--k", type=int, default=20, help="top-k retrieval hits")
        p.add_argument("--embedder", default=None, help="embedder backend")
        p.add_argument("--llm-backend", default=None, help="LLM backend")

    # incident mode
    inc_p = sub.add_parser("incident", help="Incident investigation with known description")
    add_common(inc_p)
    inc_p.add_argument("--incident", required=True, help="incident description from analyst")
    inc_p.set_defaults(func=cmd_incident)

    # assessment mode
    ass_p = sub.add_parser("assess", help="Autonomous compromise assessment")
    add_common(ass_p)
    ass_p.set_defaults(func=cmd_assess)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())