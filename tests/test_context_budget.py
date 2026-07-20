"""Tests for context budget calculator."""

from src.agents.context_budget import (
    calculate_budget,
    estimate_window_events,
)


def test_default_budget():
    budget = calculate_budget(model="glm-5.2")
    assert budget.context_window == 128_000
    assert budget.recommended_hits >= 30  # at least min_hits
    assert budget.recommended_hits <= budget.max_hits


def test_small_model():
    budget = calculate_budget(model="qwen2.5:14b")
    assert budget.context_window == 32_768
    # smaller window = fewer hits
    budget_glm = calculate_budget(model="glm-5.2")
    assert budget.recommended_hits <= budget_glm.recommended_hits


def test_no_overflow():
    """Total tokens must not exceed context window * input_ratio."""
    budget = calculate_budget(model="glm-5.2")
    total_tokens = budget.fixed_overhead + budget.recommended_hits * budget.per_hit_tokens
    max_tokens = int(budget.context_window * budget.input_ratio)
    assert total_tokens <= max_tokens


def test_min_hits():
    """Even with tiny context, should return at least min_hits."""
    budget = calculate_budget(context_window=4096, min_hits=10)
    assert budget.recommended_hits >= 10


def test_window_scaling():
    """Wider time window should allow more hits (up to cap)."""
    narrow = calculate_budget(model="glm-5.2", window_hours=0.5)
    wide = calculate_budget(model="glm-5.2", window_hours=4.0)
    assert wide.recommended_hits >= narrow.recommended_hits


def test_estimate_window_events():
    """Event estimation should scale with window and density."""
    events = estimate_window_events(
        total_events=333_945,
        window_hours=0.5,
        total_time_span_hours=365 * 24,
        density_multiplier=10.0,
    )
    assert events > 0
    # wider window = more events
    events_wide = estimate_window_events(
        total_events=333_945,
        window_hours=4.0,
        total_time_span_hours=365 * 24,
        density_multiplier=10.0,
    )
    assert events_wide > events


def test_real_case_budget():
    """Budget for SRV.nebo.ru case: 333K events, 26 min window."""
    budget = calculate_budget(
        model="glm-5.2",
        window_hours=0.43,  # 26 minutes
        total_events=333_945,
    )
    assert budget.recommended_hits >= 30
    assert budget.recommended_hits <= 200  # reasonable cap
    # verify no overflow
    total_tokens = budget.fixed_overhead + budget.recommended_hits * budget.per_hit_tokens
    assert total_tokens <= int(budget.context_window * budget.input_ratio)