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
    # Same physical private folder is not two lab observations. Check actual
    # descriptor-pinned directory identity; an alternate pathname does not
    # turn one observation into a historical baseline.
    independent_selection = (
        baseline.pop("_directory_identity") != candidate.pop("_directory_identity")
    )
    changes = []
    regressions = []
    old_status = baseline["review_status"]
    new_status = candidate["review_status"]
    if not independent_selection:
        regressions.append({"metric": "source_pair", "change": "SAME_PRIVATE_REPORT"})
    if independent_selection and old_status == "PASS" and new_status == "HOLD":
        regressions.append({"metric": "synthetic_canary", "change": "PASS_TO_HOLD"})
    if independent_selection and old_status == "PASS" and new_status == "PASS":
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
        "selection_valid": independent_selection,
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
    if result["selection_valid"] is False:
        lines.append("Same private report selected twice: this is not an independent history.")
    if result["baseline_status"] == "PASS" and result["candidate_status"] == "HOLD":
        lines.append("Synthetic status regressed from PASS to HOLD.")
    return "\n".join(lines)


def render_private_canary_history_html(result: dict) -> str:
    """Accessible scriptless anonymous M1 HUMAN review; never approval."""
    from html import escape

    state = result["review_status"]
    rows = []
    for change in result["metric_changes"]:
        label = "REGRESSION" if change["regression"] else "Informational"
        rows.append(
            "<tr><th scope='row'>" + escape(change["metric"]) + "</th>"
            "<td>" + escape(str(change["previous"])) + "</td>"
            "<td>" + escape(str(change["current"])) + "</td>"
            "<td>" + escape(label) + "</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='4'>No comparable metric changes.</td></tr>")
    content = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'\">"
        "<title>LightUp synthetic private score comparison</title>"
        "<style>body{font:16px system-ui,sans-serif;line-height:1.6;"
        "max-width:940px;margin:auto;padding:2rem}table{width:100%;"
        "border-collapse:collapse}th,td{padding:.7rem;text-align:left;"
        "border-bottom:1px solid #999}aside{border:2px solid #666;"
        "padding:1rem;margin:1rem 0}table caption{text-align:left;"
        "font-weight:600}@media(max-width:550px){body{padding:.5rem}"
        "th,td{padding:.25rem}}</style></head><body><main>"
        "<h1>LightUp synthetic HUMAN score comparison</h1><aside>"
        "<strong>NOT AUTHORIZATION</strong>. The source, reviewer identity and "
        "consent are NOT authenticated. A matching local unsigned report is not "
        "evidence authenticity, permission for real targets, security sign-off "
        "or deployment clearance.</aside><p>Original offline result: <strong>"
        + escape(result["baseline_status"]) +
        "</strong>; candidate: <strong>" + escape(result["candidate_status"]) +
        "</strong>. Comparison: <strong>" + escape(state) + "</strong>.</p>" +
        ("<p>Same original private report selected twice; no independent "
         "synthetic history accepted.</p>" if result["selection_valid"] is False
         else "") +
        "<p>Metric changes: " + str(len(result["metric_changes"])) +
        "; regressions: " + str(len(result["regressions"])) +
        ". All values are synthetic localhost scorer observations.</p>"
        "<table><caption>Original fixed synthetic metric comparison</caption>"
        "<thead><tr><th scope='col'>Metric</th><th scope='col'>Earlier</th>"
        "<th scope='col'>Later</th><th scope='col'>Review</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
        "<p>HUMAN review only. No network calls, grants, consent, scans or deploy.</p>"
        "</main></body></html>\n"
    )
    return content
