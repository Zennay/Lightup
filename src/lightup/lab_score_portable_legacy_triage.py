"""Plain-text read-only triage for legacy unsigned portable HUMAN handoffs.

Never expose unverified legacy HTML to a browser. The source-free JSON flags
are only UNSIGNED CLAIMS, not authenticated original evidence or approval.
"""
from __future__ import annotations

from typing import Any


def legacy_triage(summary: dict[str, Any]) -> str:
    """Render bounded, explicitly untrusted ordinal claims for CLI inspection."""
    n = summary["archives_checked"]
    pairs = summary["pairs"]
    holds = [item for item in pairs if not item["passed"]]
    lines = [
        "LEGACY READ-ONLY TRIAGE — HOLD; original source NOT authenticated.",
        f"Untrusted anonymous claims: {n} archives, {len(pairs)} original pairs, "
        f"{len(holds)} claimed HOLD pairs.",
        "No legacy HTML published. Pair flags are unsigned and cannot "
        "grant review approval, external target access or deployment.",
    ]
    for pair in holds:
        reasons = []
        if not pair["independent_evaluations"]:
            reasons.append("evidence reused")
        if not pair["score_stable"]:
            reasons.append("score drift")
        lines.append(
            f"Claimed HOLD {pair['previous_index']}-{pair['current_index']}: "
            + ", ".join(reasons) + "."
        )
    if not holds:
        lines.append("No HOLD pair claimed, but legacy sources remain unverified: HOLD.")
    for item in summary["archive_review_queue"]:
        lines.append(
            f"Claimed priority archive {item['index']}: "
            f"{item['hold_pairs']} HOLD pairs, "
            f"{item['reused_evidence_pairs']} reuse, "
            f"{item['score_drift_pairs']} drift."
        )
    return "\n".join(lines)
