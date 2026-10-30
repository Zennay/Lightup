"""Focused, read-only operator triage of an admitted offline synthetic ZIP.

Every pair touching one ordinal is returned, including PASS pairs, while
global HOLD and all source-authentication disclaimers remain unchanged.
This is not identity matching, authorization, or independent provenance.
"""
from __future__ import annotations

from typing import Any


class InvalidPortableSelection(ValueError):
    """A verified source-free transport has no such original ordinal selection."""


def build_portable_focus(summary: dict[str, Any], index: int) -> dict[str, Any]:
    n = summary["archives_checked"]
    if type(index) is not int or not 1 <= index <= n:
        raise InvalidPortableSelection("focused archive index out of 1-based anonymous range")
    relevant = sorted(
        (p for p in summary["pairs"]
         if index in (p["previous_index"], p["current_index"])),
        key=lambda p: (p["passed"], p["previous_index"], p["current_index"]),
    )
    if len(relevant) != n - 1:
        raise InvalidPortableSelection("incomplete original focused archive comparisons")
    pairs = []
    for p in relevant:
        reasons = []
        if not p["independent_evaluations"]:
            reasons.append("evidence_reused")
        if not p["score_stable"]:
            reasons.append("score_drift")
        pairs.append({
            "previous_index": p["previous_index"],
            "current_index": p["current_index"],
            "review_status": "PASS" if p["passed"] else "HOLD",
            "independent_evaluations": p["independent_evaluations"],
            "score_stable": p["score_stable"],
            "hold_reasons": reasons,
        })
    holds = sum(p["review_status"] == "HOLD" for p in pairs)
    return {
        "archive_index": index,
        "comparisons": len(pairs),
        "hold_pairs": holds,
        "pairs": pairs,
    }


def render_portable_focus(focus: dict[str, Any], *,
                          global_status: str, legacy: bool) -> str:
    prefix = "UNTRUSTED CLAIM: " if legacy else "Synthetic-only: "
    status = "HOLD" if legacy else global_status
    lines = [
        f"{prefix}Focused anonymous archive {focus['archive_index']}: "
        f"{focus['comparisons']} original comparisons, "
        f"{focus['hold_pairs']} focused HOLD.",
        f"GLOBAL STATUS {status}; a local PASS never clears a global HOLD.",
        "Original source NOT authenticated; no external targets, scans, "
        "consent, grants or deployment.",
    ]
    if legacy:
        lines.append("Legacy human HTML NOT admitted; all displayed "
                     "pair claims are unsigned and NOT independently validated.")
    for pair in focus["pairs"]:
        label = f"{pair['previous_index']}-{pair['current_index']}"
        reasons = ", ".join(pair["hold_reasons"]) or "none"
        lines.append(f"{prefix}pair {label}: {pair['review_status']}; "
                     f"reasons: {reasons}.")
    return "\n".join(lines)


def build_portable_pair(summary: dict[str, Any], previous: int, current: int) -> dict[str, Any]:
    """Drill into one original anonymous pair; never alter global review status."""
    n = summary["archives_checked"]
    if (type(previous) is not int or type(current) is not int
            or not 1 <= previous < current <= n):
        raise InvalidPortableSelection("pair ordinals require 1 <= previous < current <= archives")
    matches = [p for p in summary["pairs"] if (p["previous_index"], p["current_index"]) == (previous, current)]
    if len(matches) != 1:
        raise InvalidPortableSelection("original pair not found exactly once")
    pair = matches[0]
    reasons = []
    if not pair["independent_evaluations"]:
        reasons.append("evidence_reused")
    if not pair["score_stable"]:
        reasons.append("score_drift")
    return {
        "previous_index": previous, "current_index": current,
        "review_status": "PASS" if pair["passed"] else "HOLD",
        "independent_evaluations": pair["independent_evaluations"],
        "score_stable": pair["score_stable"], "hold_reasons": reasons,
    }


def render_portable_pair(pair: dict[str, Any], *, global_status: str, legacy: bool) -> str:
    prefix = "UNTRUSTED CLAIM: " if legacy else "Synthetic-only: "
    status = "HOLD" if legacy else global_status
    reasons = ", ".join(pair["hold_reasons"]) or "none"
    return (
        f"{prefix}Original anonymous pair {pair['previous_index']}-{pair['current_index']}: "
        f"{pair['review_status']}; reasons: {reasons}.\n"
        f"GLOBAL STATUS {status}; one pair PASS never clears a global HOLD.\n"
        "Original source NOT authenticated; no external targets, scans, consent, grants or deployment."
        + (" Legacy claims unsigned and not independently validated; HTML NOT admitted." if legacy else "")
    )
