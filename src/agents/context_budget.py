"""Context budget calculator for DFIR agent.

Determines optimal number of RAG hits based on:
  - LLM context window size (tokens)
  - Fixed prompt overhead (system prompt, skills, plaso KB, follow-ups)
  - Per-hit token cost (event text + metadata)
  - Target response budget (reserve tokens for LLM output)
  - Time window size (events density per hour)

Formula:
  available_tokens = context_window * input_ratio - fixed_overhead
  max_hits = available_tokens // per_hit_tokens
  recommended_hits = min(max_hits, time_window_adjusted_cap)

  time_window_adjusted_cap = base_cap * (window_hours / reference_hours)
  (wider window = more events = need more hits to cover, but capped)

Guarantees:
  - total_input_tokens = fixed_overhead + (hits * per_hit_tokens) <= context_window * input_ratio
  - response_tokens >= context_window * (1 - input_ratio)
  - hits <= max_hits (hard limit, no context overflow)
  - hits >= min_hits (minimum for useful analysis)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ContextBudget:
    """Calculated context budget for agent run."""

    context_window: int       # LLM context window (tokens)
    input_ratio: float        # fraction of window for input (0.0-1.0)
    fixed_overhead: int       # tokens for prompts, skills, KB
    per_hit_tokens: int       # tokens per RAG hit
    min_hits: int             # minimum hits for useful analysis
    max_hits: int             # hard limit (no overflow)
    recommended_hits: int     # actual recommended count
    window_hours: float       # incident time window in hours
    total_events: int         # total events in the index
    events_in_window: int     # estimated events in time window

    def __str__(self) -> str:
        return (
            f"ContextBudget(hits={self.recommended_hits}, "
            f"tokens={self.fixed_overhead + self.recommended_hits * self.per_hit_tokens}, "
            f"window={self.window_hours:.1f}h, "
            f"events_in_window={self.events_in_window})"
        )


# Default model context windows (tokens)
MODEL_CONTEXT_WINDOWS = {
    "glm-5.2": 128_000,
    "qwen2.5:14b": 32_768,
    "qwen3.5:397b": 128_000,
    "deepseek-v4-pro": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4o": 128_000,
    "kimi-k2.7-code": 200_000,
    "default": 32_768,
}

# Fixed overhead estimates (tokens)
# System prompt: ~500 tokens
# User template: ~300 tokens
# Skills summary (15 skills): ~500 tokens
# Follow-up questions: ~600 tokens
# Plaso KB context: ~800 tokens
# Total: ~2700 tokens
DEFAULT_FIXED_OVERHEAD = 2700

# Per-hit cost: "[chunk_id] (score=0.123) event_text\n"
# Avg event text: ~200 chars -> ~50 tokens
# Chunk ID + score: ~15 chars -> ~4 tokens
# Newline: 1 token
# Total: ~55 tokens per hit
DEFAULT_PER_HIT_TOKENS = 55

# Minimum hits for useful analysis
MIN_HITS = 30

# Base cap for hits (prevents context dilution)
BASE_CAP = 150

# Reference: 1 hour window = base_cap hits
REFERENCE_HOURS = 1.0


def calculate_budget(
    model: str = "glm-5.2",
    context_window: int | None = None,
    input_ratio: float = 0.75,
    fixed_overhead: int = DEFAULT_FIXED_OVERHEAD,
    per_hit_tokens: int = DEFAULT_PER_HIT_TOKENS,
    min_hits: int = MIN_HITS,
    window_hours: float = 1.0,
    total_events: int = 0,
    events_in_window: int | None = None,
) -> ContextBudget:
    """Calculate optimal number of RAG hits for a given context window.

    Args:
        model: LLM model name (for context window lookup)
        context_window: override context window size (tokens)
        input_ratio: fraction of window for input (default 0.75 = 75%)
        fixed_overhead: tokens for prompts/skills/KB
        per_hit_tokens: tokens per RAG hit
        min_hits: minimum hits for useful analysis
        window_hours: incident time window in hours
        total_events: total events in index
        events_in_window: events in time window (estimated if None)

    Returns:
        ContextBudget with recommended_hits calculated
    """
    # Resolve context window
    if context_window is None:
        context_window = MODEL_CONTEXT_WINDOWS.get(model, MODEL_CONTEXT_WINDOWS["default"])

    # Available tokens for hits
    available_tokens = int(context_window * input_ratio) - fixed_overhead
    max_hits = max(available_tokens // per_hit_tokens, min_hits)

    # Estimate events in window if not provided
    if events_in_window is None and total_events > 0 and window_hours > 0:
        # Assume uniform distribution over total time span
        # This is a rough estimate; real distribution is clustered
        # For incident windows, events are denser than average
        events_in_window = int(total_events * (window_hours / (365 * 24)) * 10)  # 10x density
    elif events_in_window is None:
        events_in_window = 0

    # Time-window-adjusted cap: wider window = more hits, but capped
    # Formula: base_cap * sqrt(window_hours / reference_hours)
    # sqrt because doubling window doesn't double relevant events
    import math

    window_factor = math.sqrt(max(window_hours / REFERENCE_HOURS, 0.1))
    window_adjusted_cap = int(BASE_CAP * window_factor)

    # Recommended hits: min of max_hits and window_adjusted_cap, but >= min_hits
    recommended_hits = max(min(min_hits, max_hits), min(max_hits, window_adjusted_cap))

    return ContextBudget(
        context_window=context_window,
        input_ratio=input_ratio,
        fixed_overhead=fixed_overhead,
        per_hit_tokens=per_hit_tokens,
        min_hits=min_hits,
        max_hits=max_hits,
        recommended_hits=recommended_hits,
        window_hours=window_hours,
        total_events=total_events,
        events_in_window=events_in_window,
    )


def estimate_window_events(
    total_events: int,
    window_hours: float,
    total_time_span_hours: float,
    density_multiplier: float = 10.0,
) -> int:
    """Estimate events in a time window.

    Incident windows have higher event density than average.
    density_multiplier accounts for this (10x = incident is 10x denser than average).

    Args:
        total_events: total events in index
        window_hours: incident window duration in hours
        total_time_span_hours: total time span of the index in hours
        density_multiplier: how much denser incident window is vs average

    Returns:
        Estimated events in window
    """
    if total_time_span_hours <= 0:
        return 0
    base_density = total_events / total_time_span_hours
    return int(base_density * window_hours * density_multiplier)