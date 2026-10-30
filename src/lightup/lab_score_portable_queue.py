"""Bounded source-free original-pair work queue for offline HUMAN triage.

Anonymous source-free ZIP data is not original evidence authentication,
consent, ownership or authority to contact any target.
"""
from __future__ import annotations

from typing import Any
from .lab_score_portable_focus import build_portable_pair


def build_portable_queue(summary: dict[str, Any]) -> dict[str, Any]:
    """Prioritize every already-admitted original pair, no network or writes."""
    pairs = [build_portable_pair(summary, p["previous_index"], p["current_index"])
             for p in summary["pairs"]]
    # Evidence reuse is the first operator concern; score drift is second.
    # Never put PASS ahead of any HOLD, including two-reason HOLDs.
    pairs.sort(key=lambda p: (
        p["review_status"] != "HOLD",
        "evidence_reused" not in p["hold_reasons"],
        "score_drift" not in p["hold_reasons"],
        p["previous_index"], p["current_index"],
    ))
    hold_count = sum(p["review_status"] == "HOLD" for p in pairs)
    return {
        "schema": "lightup.lab-score-human-pair-queue.v1",
        "pairs_checked": len(pairs),
        "hold_pairs": hold_count,
        "pass_pairs": len(pairs) - hold_count,
        # Already checked against the canonical original pair matrix.
        "archive_priorities": [dict(item) for item in summary["archive_review_queue"]],
        "human_review_only": True,
        "source_identity_authenticated": False,
        "pairs": pairs,
    }


def render_portable_queue(queue: dict[str, Any], *,
                          global_status: str, legacy: bool) -> str:
    prefix = "UNTRUSTED CLAIM: " if legacy else "Synthetic-only: "
    state = "HOLD" if legacy else global_status
    lines = [
        f"{prefix}Original pair HUMAN review queue: {queue['pairs_checked']} pairs; "
        f"{queue['hold_pairs']} HOLD, {queue['pass_pairs']} PASS.",
        f"GLOBAL STATUS {state}; local pair PASS never clears global HOLD.",
        "Original evidence not authenticated. HUMAN review only; no external "
        "targets, scans, consent, grants or deployment.",
    ]
    if legacy:
        lines.append("Legacy queue is UNSIGNED and UNTRUSTED; never a clearance or HTML approval.")
    for archive in queue["archive_priorities"]:
        lines.append(f"{prefix}Review archive {archive['index']}: "
                     f"{archive['hold_pairs']} HOLD pairs "
                     f"({archive['reused_evidence_pairs']} replay, "
                     f"{archive['score_drift_pairs']} score drift).")
    for index, pair in enumerate(queue["pairs"], 1):
        reasons = ", ".join(pair["hold_reasons"]) or "none"
        lines.append(f"{prefix}{index}. pair {pair['previous_index']}-{pair['current_index']}: "
                     f"{pair['review_status']}; reasons: {reasons}.")
    return "\n".join(lines)
