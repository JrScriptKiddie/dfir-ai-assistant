"""Subagent architecture: one agent per artifact type.

Each subagent specializes in one forensic artifact domain:
  - EVTX subagent: Windows Event Log analysis (Security, System, Application)
  - Registry subagent: NTUSER.DAT, SYSTEM, SOFTWARE, Amcache, ShimCache
  - MFT subagent: file system timeline, malware drop, encryption patterns
  - Prefetch subagent: program execution history
  - Network subagent: logon source IPs, firewall, connections
  - UserActivity subagent: UserAssist, browser history, recently used
  - Hayabusa subagent: Sigma rule matching on EVTX

Each subagent:
  1. Has its own skill set (filtered to its domain)
  2. Queries RAG with domain-specific keywords + time window
  3. Generates a domain-specific mini-report
  4. Orchestrator merges mini-reports into final incident report

Architecture:
```
[Orchestrator Agent]
  ├── EVTX Subagent      -> evtx_report.md
  ├── Registry Subagent  -> registry_report.md
  ├── MFT Subagent       -> mft_report.md
  ├── Prefetch Subagent  -> prefetch_report.md
  ├── Network Subagent   -> network_report.md
  ├── UserActivity       -> user_report.md
  └── Hayabusa Subagent  -> sigma_alerts.md
       |
       v
  [Merged Final Report]
```

Context budget per subagent:
  - Each subagent gets a fraction of total context budget
  - budget_per_subagent = total_budget / num_subagents
  - But weighted by relevance (EVTX gets more in incident mode)
  - Orchestrator gets summary from each, not raw hits
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .context_budget import ContextBudget
from .skills import Skill


@dataclass
class SubagentSpec:
    """Specification for a domain-specific subagent."""

    name: str
    artifact_type: str
    description: str
    skills: list[Skill] = field(default_factory=list)
    context_weight: float = 1.0  # relative context budget weight
    time_window_required: bool = True


# Subagent definitions (skills assigned from existing skill set)
# These will be populated from skills.py when subagents are implemented
SUBAGENT_SPECS = [
    SubagentSpec(
        name="evtx_agent",
        artifact_type="EVTX",
        description="Windows Event Log analysis: Security (4624/4625/7045), System, Application",
        context_weight=2.0,  # EVTX is usually the richest source
    ),
    SubagentSpec(
        name="registry_agent",
        artifact_type="REG",
        description="Registry analysis: persistence, Amcache, ShimCache, UserAssist, Run keys",
        context_weight=1.5,
    ),
    SubagentSpec(
        name="mft_agent",
        artifact_type="MFT",
        description="MFT analysis: file creation, malware drop, encryption timeline, deletion",
        context_weight=1.5,
    ),
    SubagentSpec(
        name="prefetch_agent",
        artifact_type="PREFETCH",
        description="Prefetch analysis: program execution history, run count, loaded DLLs",
        context_weight=1.0,
    ),
    SubagentSpec(
        name="network_agent",
        artifact_type="NETWORK",
        description="Network analysis: source IPs, logon correlation, firewall, connections",
        context_weight=1.5,
    ),
    SubagentSpec(
        name="user_activity_agent",
        artifact_type="USER",
        description="User activity: UserAssist, browser history, recently used files",
        context_weight=1.0,
    ),
    SubagentSpec(
        name="hayabusa_agent",
        artifact_type="SIGMA",
        description="Hayabusa Sigma rule matching on EVTX: pre-built detection rules",
        context_weight=1.0,
    ),
]


def allocate_budget_per_subagent(
    total_budget: ContextBudget,
    active_subagents: list[SubagentSpec] | None = None,
) -> dict[str, ContextBudget]:
    """Allocate context budget across subagents weighted by relevance.

    Args:
        total_budget: total context budget for the run
        active_subagents: list of active subagent specs (default: all)

    Returns:
        Dict mapping subagent name -> ContextBudget
    """
    if active_subagents is None:
        active_subagents = SUBAGENT_SPECS

    total_weight = sum(sa.context_weight for sa in active_subagents)
    budgets: dict[str, ContextBudget] = {}

    for sa in active_subagents:
        fraction = sa.context_weight / total_weight
        subagent_hits = max(
            int(total_budget.recommended_hits * fraction),
            10,  # minimum 10 hits per subagent
        )
        sub_budget = ContextBudget(
            context_window=total_budget.context_window,
            input_ratio=total_budget.input_ratio,
            fixed_overhead=total_budget.fixed_overhead,
            per_hit_tokens=total_budget.per_hit_tokens,
            min_hits=10,
            max_hits=subagent_hits,
            recommended_hits=subagent_hits,
            window_hours=total_budget.window_hours,
            total_events=total_budget.total_events,
            events_in_window=total_budget.events_in_window,
        )
        budgets[sa.name] = sub_budget

    return budgets