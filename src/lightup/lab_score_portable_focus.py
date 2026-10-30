"""Focused, read-only operator triage of an admitted offline synthetic ZIP.

Every pair touching one ordinal is returned, including PASS pairs, while
global HOLD and all source-authentication disclaimers remain unchanged.
This is not identity matching, authorization, or independent provenance.
"""
from __future__ import annotations

from typing import Any


def build_portable_focus(summary: dict[str, Any], index: int) -> dict[str, Any]:
    n = summary["archives_checked"]
    if type(index) is not int or not 1 <= index <= n:
        raise ValueError("focused archive index out of 1-based anonymous range")
    relevant = sorted(
        (p for p in summary["pairs"]
         if index in (p["previous_index"], p["current_index"])),
        key=lambda p: (p["passed"], p["previous_index"], p["current_index"]),
    )
    if len(relevant) != n - 1:
        raise ValueError("incomplete original focused archive comparisons")
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
