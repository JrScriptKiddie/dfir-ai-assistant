"""Tests for subagent specs and budget allocation."""

from src.agents.subagents import (
    SUBAGENT_SPECS,
    allocate_budget_per_subagent,
)
from src.agents.context_budget import calculate_budget


def test_subagent_specs_exist():
    assert len(SUBAGENT_SPECS) >= 7
    names = {sa.name for sa in SUBAGENT_SPECS}
    assert "evtx_agent" in names
    assert "registry_agent" in names
    assert "mft_agent" in names
    assert "hayabusa_agent" in names


def test_subagent_weights():
    """EVTX should have higher weight than prefetch."""
    evtx = next(sa for sa in SUBAGENT_SPECS if sa.name == "evtx_agent")
    prefetch = next(sa for sa in SUBAGENT_SPECS if sa.name == "prefetch_agent")
    assert evtx.context_weight > prefetch.context_weight


def test_budget_allocation():
    """Budget should be allocated across subagents, sum <= total."""
    total = calculate_budget(model="glm-5.2", window_hours=1.0)
    budgets = allocate_budget_per_subagent(total)
    assert len(budgets) == len(SUBAGENT_SPECS)
    # each subagent gets at least 10 hits
    for name, budget in budgets.items():
        assert budget.recommended_hits >= 10, f"{name} got {budget.recommended_hits}"
    # EVTX should get more than prefetch
    assert budgets["evtx_agent"].recommended_hits >= budgets["prefetch_agent"].recommended_hits


def test_budget_allocation_subset():
    """Can allocate to a subset of subagents."""
    total = calculate_budget(model="glm-5.2")
    subset = [SUBAGENT_SPECS[0], SUBAGENT_SPECS[1]]  # first two
    budgets = allocate_budget_per_subagent(total, active_subagents=subset)
    assert len(budgets) == 2