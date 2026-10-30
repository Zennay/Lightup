"""Read-only paired synthetic M1 canary history: never a release verdict.

Both original owner-private handoffs are fully admitted before any metric is
compared. This measures *local synthetic* drift, not evidence authenticity,
real target permission, security findings or deployment readiness.
"""
from __future__ import annotations

from .lab_canary_handoff import _read_private_canary_handoff

SCORERS = ("service_inventory", "tls_baseline", "web_baseline")
METRICS = (
    ("valid_findings", "decrease"),
    ("invalid_findings", "increase"),
    ("missed_findings", "increase"),
    ("reproducibility", "decrease"),
    ("evidence_quality", "decrease"),
)


def compare_private_canary_handoffs(before: str, after: str) -> dict:
    """Deterministic no-write comparison from two independently admitted dirs."""
    # Reading both via descriptor-pinned canonical bytes ensures the verdict
    # cannot use a pathname re-read after verification (no TOCTOU).
    baseline = _read_private_canary_handoff(before)
    candidate = _read_private_canary_handoff(after)
    old = baseline.pop("_admitted_canary")
    new = candidate.pop("_admitted_canary")
    changes = []
    regressions = []
    old_status = baseline["review_status"]
    new_status = candidate["review_status"]
    if old_status == "PASS" and new_status == "HOLD":
        regressions.append({"metric": "synthetic_canary", "change": "PASS_TO_HOLD"})
    if old_status == "PASS" and new_status == "PASS":
        for scorer in SCORERS:
            for suffix, unfavorable in METRICS:
                metric = f"{scorer}_{suffix}"
                previous = old[metric]
                current = new[metric]
                if previous == current:
                    continue
                regression = (current < previous if unfavorable == "decrease"
                              else current > previous)
                item = {
                    "metric": metric, "previous": previous,
                    "current": current, "regression": regression,
                }
                changes.append(item)
                if regression:
                    regressions.append(item)
    status = ("PASS" if old_status == new_status == "PASS" and not regressions
              else "HOLD")
    return {
        "schema": "lightup.m1.synthetic-private-canary-history.v1",
        "baseline_status": old_status,
        "candidate_status": new_status,
        "review_status": status,
        "input_integrity": True,
        "metric_changes": changes,
        "regressions": regressions,
        "synthetic_loopback_only": True,
        "source_authenticated": False,
        "consent_authenticated": False,
        "authorization_granted": False,
        "external_target_authorized": False,
        "deployment": False,
        "human_review_only": True,
    }


def render_private_canary_comparison(result: dict) -> str:
    """Only stable anonymous allowlisted metrics and fixed labels leave memory."""
    lines = [
        f"LightUp synthetic canary history: {result['review_status']}",
        f"Earlier: {result['baseline_status']}; later: {result['candidate_status']}.",
        f"Local scorer changes: {len(result['metric_changes'])}; "
        f"regressions: {len(result['regressions'])}.",
        "Original sources and consent NOT authenticated. HUMAN review only.",
        "No external target, scanning, authorization or deployment clearance.",
    ]
    for change in result["metric_changes"]:
        lines.append(
            f"{change['metric']}: {change['previous']} -> {change['current']} "
            f"({'REGRESSION' if change['regression'] else 'informational'})."
        )
    if result["baseline_status"] == "PASS" and result["candidate_status"] == "HOLD":
        lines.append("Synthetic status regressed from PASS to HOLD.")
    return "\n".join(lines)
