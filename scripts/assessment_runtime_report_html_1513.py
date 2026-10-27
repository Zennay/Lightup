"""Portable, script-free offline HTML view of already-admitted lab comparisons.

Only structured, source-reported metric data is rendered; original scenario IDs,
record IDs, input paths, asset names, note text and client identifiers are never
interpolated. No browser network capability or authorization signal is emitted.
"""
from __future__ import annotations

from base64 import b64encode
from collections import Counter
from csv import writer as csv_writer
from decimal import Decimal, localcontext
from io import StringIO
from json import dumps as json_dumps
from hashlib import sha256
from html import escape


_STYLES = """
:root{color-scheme:light;font-family:system-ui,-apple-system,sans-serif;color:#172438;background:#f3f6fa}
*{box-sizing:border-box}body{margin:0 auto;padding:2rem;max-width:1200px;line-height:1.55}
header{padding:1.8rem;border-radius:1.2rem;background:#172d47;color:#fff}
h1{font-size:clamp(1.5rem,3vw,2.4rem);line-height:1.2;margin:.25rem 0 1rem}
h2{font-size:1.35rem;margin:0 0 .8rem}h3{font-size:1.13rem;margin:0 0 .8rem}
p{margin:.55rem 0}.eyebrow{text-transform:uppercase;letter-spacing:.1em;font-size:.77rem;opacity:.85}
.badge{display:inline-block;border:1px solid currentColor;border-radius:1rem;padding:.22rem .75rem;font-weight:700}
.panel{margin:1rem 0;padding:1.2rem 1.4rem;border:1px solid #d7e0eb;border-radius:1rem;background:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem;margin:1rem 0}
.stat{padding:1rem;border:1px solid #d7e0eb;border-radius:.7rem;background:#fff}
.stat b{font-size:1.5rem;display:block;font-variant-numeric:tabular-nums}
.stat span{font-size:.86rem;color:#46566b}.warning{border-left:5px solid #995008;background:#fff8e9}
.hold{background:#ffe9e6;color:#852b23}.review{background:#e0f0ec;color:#105044}
.muted{color:#55677b}.table-scroll{width:100%;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:.57rem .7rem;border-bottom:1px solid #e1e6ee;text-align:left;white-space:nowrap}
th{background:#eef2f7;color:#172c44}tbody tr:nth-child(even){background:#f9fbfd}
.flag{font-weight:700;color:#9a3026}.neutral{color:#4e6276}
nav{display:flex;flex-wrap:wrap;gap:.65rem;margin:1rem 0}
nav a{border:1px solid #bed0e0;border-radius:.55rem;padding:.4rem .75rem;color:#24405e}
strong{font-weight:700}.foot{font-size:.88rem;color:#4d5e71}
@media print{
  :root{color-scheme:light}body{padding:0;max-width:none;font:10pt Georgia,serif;background:white}
  header{border:1px solid #444;background:white;color:black}
  .panel,.stat{break-inside:avoid;box-shadow:none}nav{display:none}
  table{font-size:8pt}tr{break-inside:avoid}h2,h3{break-after:avoid}
}
"""

# The comparator, not this output surface, makes the adverse-metric decision.
_METRIC_LABELS = {
    "valid_findings": "Valid findings",
    "invalid_findings": "Invalid findings",
    "missed_findings": "Missed findings",
    "coverage_assessed": "Assessed coverage",
    "coverage_unknown": "Unknown coverage",
    "scope_violations": "Scope violations",
    "policy_violations": "Policy violations",
    "human_interventions": "Human interventions",
    "tool_calls": "Tool calls",
    "evidence_quality": "Evidence quality",
    "reproducibility": "Reproducibility",
    "remediation_quality": "Remediation quality",
    "retest_correctness": "Retest correctness",
    "runtime_seconds": "Runtime seconds",
    "compute_cost_usd": "Compute cost USD",
}
_OPERATIONAL = frozenset(("human_interventions", "tool_calls", "runtime_seconds", "compute_cost_usd"))
_UNCERTAIN = "coverage_unknown"


def _safe(value: object) -> str:
    return escape(str(value), quote=True)


def _label(name: str) -> str:
    # Only known, fixed metric names may be visible to the offline viewer.
    return _safe(_METRIC_LABELS.get(name, "Unclassified metric"))


def _metric_rows(changes, *, prefix: str = "") -> str:
    rows = []
    for change in changes:
        # Prevent unknown user-controlled field names from escaping as labels.
        label = _label(change.name)
        flag = bool(change.regression)
        note = ("SOURCE-FLAGGED" if flag else
                "Uncertainty, not a regression" if change.name == _UNCERTAIN else
                "Informational only" if change.name in _OPERATIONAL else
                "Not source-flagged")
        style = "flag" if flag else "neutral"
        cells = (
            label, _safe(change.baseline), _safe(change.candidate),
            _safe(change.delta), '<span class="' + style + '">' + note + '</span>',
        )
        rows.append("<tr>" + "".join("<td>" + c + "</td>" for c in cells) + "</tr>")
    if not rows:
        return "<p class='muted'>No accepted metric details were available.</p>"
    headers = ("Metric", "Baseline", "Candidate", "Delta", "Source-reported interpretation")
    return (
        '<div class="table-scroll"><table><thead><tr>' +
        "".join("<th scope='col'>" + h + "</th>" for h in headers) +
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _ranked_human_actions(accepted):
    """Stable offline HUMAN review order, not a severity or authority verdict."""
    options = []
    for ordinal, comp in enumerate(accepted, 1):
        scope = any(
            c.name in ("scope_violations", "policy_violations")
            and c.candidate > 0 for c in comp.changes
        )
        unknown = next((c.candidate for c in comp.changes
                        if c.name == _UNCERTAIN), 0)
        flags = len(comp.regressions)
        if scope:
            group, priority, question = (
                "Scope/policy", 0,
                "Ask the original owner to clarify reported scope/policy signals.")
        elif flags:
            group, priority, question = (
                "Adverse source metrics", 1,
                "Request independent review of source-reported adverse metrics.")
        elif unknown > 0:
            group, priority, question = (
                "Unknown coverage", 2,
                "Clarify the source-reported unknown-coverage gap.")
        else:
            group, priority, question = (
                "Source verification", 3,
                "Reconcile original source identity; no flags is not approval.")
        options.append((priority, -flags, -unknown, ordinal,
                        group, flags, unknown, question, scope))
    return tuple(
        (rank, ordinal, group, flags, unknown, question, scope)
        for rank, (
            _priority, _negative_flags, _negative_unknown, ordinal, group,
            flags, unknown, question, scope
        ) in enumerate(sorted(options), 1)
    )


def _followup_queue(accepted) -> str:
    """HTML uses the same reviewed ordering as the private HUMAN CSV."""
    rows = []
    for rank, ordinal, group, flags, unknown, question, _scope in _ranked_human_actions(accepted):
        rows.append(
            "<tr><td>" + str(rank) + "</td><td><a href='#scenario-"
            + str(ordinal) + "'>Scenario " + str(ordinal).zfill(2)
            + "</a></td><td>" + _safe(group) + "</td><td>"
            + str(flags) + "</td><td>" + _safe(unknown)
            + "</td><td>" + _safe(question) + "</td></tr>"
        )
    if not rows:
        return ""
    return (
        '<section class="panel"><h2>Suggested HUMAN follow-up order</h2>'
        '<p class="muted">Original source-declared scope/policy signals, '
        'then adverse metrics, unknown coverage and source verification. '
        'Within each group, higher flag count and unknown coverage come first; '
        'original anonymous ordinal breaks ties. No severity, proof or GO.</p>'
        '<div class="table-scroll"><table><thead><tr>'
        '<th scope="col">Review order</th><th scope="col">Anonymous case</th>'
        '<th scope="col">Review group</th><th scope="col">Adverse flags</th>'
        '<th scope="col">Unknown coverage</th>'
        '<th scope="col">Suggested HUMAN question</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div></section>'
    )



def render_comparison_html(result, *, cohort: bool = False,
                           scored: bool = False) -> str:
    """Create an offline printable review, without external assets or raw IDs.

    The input is a completed comparison result, never raw user-supplied JSON.
    A rejected input has no comparisons/changes, and therefore emits no
    partly-admitted scenario or numeric details.
    """
    if cohort:
        accepted = tuple(comp for _source_id, comp in result.comparisons)
    else:
        accepted = (result,) if result.changes else ()
    flagged = sum(bool(comp.regressions) for comp in accepted)
    counts = Counter(
        change.name for comp in accepted
        for change in comp.changes if change.regression
    )
    unknown = [
        change.candidate for comp in accepted for change in comp.changes
        if change.name == _UNCERTAIN
    ]
    unknown_positive = sum(value > 0 for value in unknown)
    accepted_total = len(accepted)
    report_kind = "Scored cohort" if scored else "Cohort" if cohort else "Single-case"
    state = "HOLD" if result.status != "REVIEW_ONLY" else "REVIEW_ONLY"
    headline = ("The source-reported comparison contains adverse flags."
                if accepted and flagged else
                "No source-reported adverse flags; this is not release approval."
                if accepted else
                "Admission or consistency did not permit a complete comparison.")
    style_pin = b64encode(sha256(_STYLES.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; base-uri 'none'; form-action 'none'; "
              "connect-src 'none'; img-src 'none'; font-src 'none'; "
              "object-src 'none'; frame-src 'none'; script-src 'none'; "
              "style-src 'sha256-" + style_pin + "'")
    summary = (
        '<div class="grid" aria-label="Comparison summary">' +
        _stat(accepted_total, "Accepted anonymous scenarios") +
        _stat(flagged, "Scenarios with adverse source flags") +
        _stat(sum(counts.values()), "Source-reported adverse metric flags") +
        _stat(str(unknown_positive) + " / " + str(len(unknown)),
              "Unknown-coverage values above zero") +
        "</div>"
    )
    followup = _followup_queue(accepted)
    distribution_rows = "".join(
        "<tr><td>" + _label(name) + "</td><td>" + str(counts[name]) +
        "</td></tr>"
        for name in _METRIC_LABELS if counts[name]
    )
    distribution = (
        "<h2>Source-reported adverse metric distribution</h2>" +
        ('<div class="table-scroll"><table><thead><tr><th scope="col">Metric</th>' +
         '<th scope="col">Flagged scenarios</th></tr></thead><tbody>' +
         distribution_rows + '</tbody></table></div>'
         if distribution_rows else
         "<p>No metric was source-flagged in the admitted comparison.</p>")
    )
    sections = []
    for idx, comp in enumerate(accepted, 1):
        title = ("Scenario " + str(idx).zfill(2)) if cohort else "Single lab comparison"
        indicator = ("HOLD: source-reported adverse metrics" if comp.regressions
                     else "REVIEW_ONLY: no adverse metric flags")
        sections.append(
            '<section class="panel" id="scenario-' + str(idx) + '">' +
            "<h3>" + title + "</h3><p class='muted'>" + indicator + "</p>" +
            _metric_rows(comp.changes) + "</section>"
        )
    nav = (
        "<nav aria-label='Jump to anonymous scenario'>"+
        "".join('<a href="#scenario-' + str(i) + '">Scenario ' +
                str(i).zfill(2) + "</a>" for i in range(1, len(sections)+1)) +
        "</nav>"
    ) if cohort and len(sections) > 1 else ""
    details = (nav + "".join(sections) if sections else
               "<section class='panel warning'><h2>No comparison details</h2>"
               "<p>Input admission or consistency failed. No partial metric "
               "values, scenario IDs, paths or payloads are disclosed.</p></section>")
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>" +
        "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
        "<meta name='referrer' content='no-referrer'>" +
        '<meta http-equiv="Content-Security-Policy" content="' +
        escape(policy, quote=True) + '">' +
        "<title>LightUp offline lab comparison — " + state + "</title>" +
        "<style>" + _STYLES + "</style></head><body>" +
        "<header><p class='eyebrow'>LightUp · private local diagnostic</p>" +
        "<h1>" + report_kind + " assessment-runtime review</h1>" +
        "<p><span class='badge " + ("review" if state == "REVIEW_ONLY" else "hold") +
        "'>Source status: " + state + "</span></p>" +
        "<p>" + headline + "</p></header>" +
        '<section class="panel warning"><h2>Authority boundary</h2>' +
        "<p>PLAN/LAB ONLY. This is an unauthenticated, source-reported, "
        "human review of previously recorded data—not a pass, independently "
        "verified ground truth, remediation proof, client/operator consent, "
        "authorization, dispatch instruction or release approval.</p>" +
        "<p><strong>authorized=false · consent_verified=false · "
        "dispatch_allowed=false · release_allowed=false</strong></p>" +
        "<p>No real target, network, browser script, grant, handler or "
        "deployment is needed to view this file.</p></section>" +
        summary + followup + '<section class="panel">' + distribution + "</section>" +
        "<h2>Anonymous scenario detail</h2>" + details +
        "<footer class='panel foot'><p>Only admitted metric numbers and fixed "
        "labels appear here. Original scenario IDs, source paths, target "
        "addresses, client names and notes are deliberately omitted.</p>" +
        "<p>Any zero-adverse result remains REVIEW_ONLY, never GO. "
        "All existing security, privacy, original CI and explicit HUMAN GO "
        "requirements remain mandatory.</p></footer></body></html>\n"
    )


def _stat(number, caption: str) -> str:
    return '<div class="stat"><b>' + _safe(number) + '</b><span>' + _safe(caption) + '</span></div>'


def render_comparison_csv(result, *, cohort: bool = False,
                          scored: bool = False) -> str:
    """Long-form spreadsheet handoff with anonymous ordinals and fixed labels.

    CSV output is a local diagnostic. Values are admitted comparator numeric
    fields, never original untrusted text. Negative numeric deltas are kept as
    actual negative numbers rather than reinterpreted as spreadsheet formulas.
    """
    file = StringIO(newline="")
    out = csv_writer(file, lineterminator="\r\n")
    out.writerow((
        "report_type", "source_status", "input_admitted",
        "scenario_ordinal", "metric", "baseline", "candidate", "delta",
        "source_regression_flag", "source_unknown_coverage",
        "authorized", "consent_verified", "dispatch_allowed",
        "release_allowed", "review_only", "source_provenance_authenticated",
    ))
    if cohort:
        accepted = tuple(comp for _source_id, comp in result.comparisons)
    else:
        accepted = (result,) if result.changes else ()
    kind = "scored_cohort" if scored else "cohort" if cohort else "single_case"
    status = "REVIEW_ONLY" if result.status == "REVIEW_ONLY" else "HOLD"
    for ordinal, comparison in enumerate(accepted, 1):
        for change in comparison.changes:
            if change.name not in _METRIC_LABELS:
                # A raw, potentially formula-leading name is never exported.
                metric = "unclassified_metric"
            else:
                metric = change.name
            out.writerow((
                kind, status, "true", ordinal, metric, change.baseline,
                change.candidate, change.delta,
                "true" if change.regression else "false",
                "true" if change.name == _UNCERTAIN and change.candidate > 0 else "false",
                "false", "false", "false", "false", "true", "false",
            ))
    if not accepted:
        # The only rejected-input row contains a generic HOLD and no partial
        # details; file creation itself is not a signal of accepted input.
        out.writerow((kind, "HOLD", "false", 0, "not_available",
                      "", "", "", "false", "false",
                      "false", "false", "false", "false", "true", "false"))
    return file.getvalue()


_HUMAN_FOCUS_GROUPS = {
    "all": None,
    "scope": "Scope/policy",
    "adverse": "Adverse source metrics",
    "unknown": "Unknown coverage",
    "source": "Source verification",
}


def _select_human_actions(result, *, cohort: bool, focus: str):
    """Admit the complete comparison before selecting HUMAN-only review rows."""
    if type(focus) is not str or focus not in _HUMAN_FOCUS_GROUPS:
        raise ValueError("invalid HUMAN focus selection")
    accepted = (
        tuple(comp for _source_id, comp in result.comparisons) if cohort
        else (result,) if result.changes else ()
    )
    actions = _ranked_human_actions(accepted)
    selected = tuple(
        item for item in actions
        if _HUMAN_FOCUS_GROUPS[focus] in (None, item[2])
    )
    return actions, selected


def render_human_actions_csv(result, *, cohort: bool = False,
                             scored: bool = False, focus: str = "all") -> str:
    """Private, ordinal-only HUMAN queue with auditable subset context."""
    actions, selected = _select_human_actions(
        result, cohort=cohort, focus=focus,
    )
    file = StringIO(newline="")
    out = csv_writer(file, lineterminator="\r\n")
    out.writerow((
        "report_type", "source_status", "input_admitted", "focus_filter",
        "accepted_case_count", "selected_case_count", "review_order",
        "scenario_ordinal", "human_review_group", "scope_policy_signal",
        "source_adverse_metric_count", "source_unknown_coverage",
        "suggested_human_question", "authorized", "consent_verified",
        "dispatch_allowed", "release_allowed", "source_provenance_authenticated",
    ))
    kind = "scored_cohort" if scored else "cohort" if cohort else "single_case"
    status = "REVIEW_ONLY" if result.status == "REVIEW_ONLY" else "HOLD"
    for rank, ordinal, group, flags, unknown, question, scope in selected:
        out.writerow((
            kind, status, "true", focus, len(actions), len(selected),
            rank, ordinal, group, "true" if scope else "false",
            flags, unknown, question,
            "false", "false", "false", "false", "false",
        ))
    if not actions:
        out.writerow((
            kind, "HOLD", "false", focus, 0, 0, 0, 0, "Input HOLD",
            "false", 0, "",
            "Ask the original owner to check input admission and consistency.",
            "false", "false", "false", "false", "false",
        ))
    elif not selected:
        out.writerow((
            kind, status, "true", focus, len(actions), 0, 0, 0,
            "No matching HUMAN cases", "false", 0, "",
            "No case in this selected group; review the full source separately.",
            "false", "false", "false", "false", "false",
        ))
    return file.getvalue()



_EFFICIENCY_FIELDS = ("runtime_seconds", "compute_cost_usd")


def _resource_decimal_sum(left: Decimal, right: Decimal) -> Decimal:
    # Finite Python floats range from ~1e-324 to ~1e308; exact sums need
    # far more than the default 28 significant Decimal digits.
    with localcontext() as context:
        context.prec = 800
        return left + right


def _resource_decimal_delta(old: Decimal, new: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 800
        return new - old


def _efficiency_data(result, *, cohort: bool, scored: bool):
    """Complete-source, ordinal-only efficiency observations. No budget verdict."""
    kind = "scored_cohort" if scored else "cohort" if cohort else "single_case"
    source_status = "REVIEW_ONLY" if result.status == "REVIEW_ONLY" else "HOLD"
    accepted = (
        tuple(comp for _source_id, comp in result.comparisons) if cohort
        else (result,) if result.changes else ()
    )
    totals = {
        name: {"baseline": Decimal(0), "candidate": Decimal(0),
               "increased_cases": 0, "decreased_cases": 0}
        for name in _EFFICIENCY_FIELDS
    }
    cases = []
    valid = bool(accepted)
    for ordinal, comp in enumerate(accepted, 1):
        metrics = {
            name: [change for change in comp.changes if change.name == name]
            for name in _EFFICIENCY_FIELDS
        }
        if any(len(metrics[name]) != 1 for name in _EFFICIENCY_FIELDS):
            valid = False
            break
        observed = {}
        for name in _EFFICIENCY_FIELDS:
            change = metrics[name][0]
            old, new = Decimal(str(change.baseline)), Decimal(str(change.candidate))
            if (not old.is_finite() or not new.is_finite()
                    or old < 0 or new < 0):
                valid = False
                break
            delta = _resource_decimal_delta(old, new)
            with localcontext() as context:
                context.prec = 12
                percent = str((delta / old) * 100) if old else None
            direction = "increase" if delta > 0 else "decrease" if delta < 0 else "unchanged"
            observed[name] = {
                "baseline": str(old), "candidate": str(new),
                "delta": str(delta), "percent_change": percent,
                "direction": direction,
            }
            totals[name]["baseline"] = _resource_decimal_sum(totals[name]["baseline"], old)
            totals[name]["candidate"] = _resource_decimal_sum(totals[name]["candidate"], new)
            if delta > 0:
                totals[name]["increased_cases"] += 1
            elif delta < 0:
                totals[name]["decreased_cases"] += 1
        if not valid:
            break
        cases.append({"scenario_ordinal": ordinal, "metrics": observed})

    if not valid:
        # No partial accepted packet or metric leaks across a held batch.
        cases = []
        totals = {}
    else:
        totals = {
            name: {
                "baseline_total": str(values["baseline"]),
                "candidate_total": str(values["candidate"]),
                "delta_total": str(_resource_decimal_delta(values["baseline"], values["candidate"])),
                "increased_cases": values["increased_cases"],
                "decreased_cases": values["decreased_cases"],
            }
            for name, values in totals.items()
        }
    return {
        "schema_version": 1,
        "report_type": kind,
        "source_status": source_status if valid else "HOLD",
        "input_admitted": valid,
        "readout": "informational_only" if valid else "input_hold",
        "accepted_case_count": len(cases),
        "cases": cases,
        "aggregate": totals,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_provenance_authenticated": False,
    }


def render_efficiency_json(result, *, cohort: bool = False,
                           scored: bool = False) -> str:
    """Privacy-minimal resource deltas over already accepted offline lab metrics."""
    return json_dumps(
        _efficiency_data(result, cohort=cohort, scored=scored),
        sort_keys=True, separators=(",", ":"),
    ) + "\n"


def render_efficiency_html(result, *, cohort: bool = False,
                           scored: bool = False) -> str:
    """Scriptless printable review of resource observations, not cost approval."""
    data = _efficiency_data(result, cohort=cohort, scored=scored)
    rows = []
    for item in data["cases"]:
        for name in _EFFICIENCY_FIELDS:
            metric = item["metrics"][name]
            values = (
                "Scenario " + str(item["scenario_ordinal"]).zfill(2),
                _METRIC_LABELS[name], metric["baseline"], metric["candidate"],
                metric["delta"], metric["percent_change"] or "n/a (zero baseline)",
                metric["direction"],
            )
            rows.append("<tr>" + "".join("<td>" + _safe(v) + "</td>" for v in values) + "</tr>")
    if not rows:
        rows.append(
            '<tr><td colspan="7">Input HOLD: no complete admitted resource '
            "comparison is available.</td></tr>"
        )
    pin = b64encode(sha256(_STYLES.encode("utf-8")).digest()).decode("ascii")
    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; frame-src 'none'; script-src 'none'; "
        "style-src 'sha256-" + pin + "'"
    )
    heads = (
        "Anonymous case", "Source metric", "Baseline", "Candidate",
        "Delta", "Change (%)", "Direction",
    )
    aggregates = []
    for name in _EFFICIENCY_FIELDS:
        values = data["aggregate"].get(name)
        if values is not None:
            aggregates.append(
                "<p><strong>" + _safe(_METRIC_LABELS[name]) + "</strong>: "
                "source totals " + _safe(values["baseline_total"]) + " → "
                + _safe(values["candidate_total"]) + ", delta "
                + _safe(values["delta_total"]) + ", increases in "
                + _safe(values["increased_cases"]) + " cases; decreases in "
                + _safe(values["decreased_cases"]) + " cases.</p>"
            )
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="'
        + escape(policy, quote=True) + '">'
        "<title>LightUp offline lab efficiency observations</title>"
        "<style>" + _STYLES + "</style></head><body>"
        "<header><p class='eyebrow'>LightUp · offline lab observations</p>"
        "<h1>Resource change summary</h1><p><span class='badge'>"
        + _safe(data["source_status"]) + " · INFORMATIONAL ONLY</span></p></header>"
        '<div class="grid">'
        + _stat(data["accepted_case_count"], "Admitted anonymous cases")
        + _stat("No verdict", "Performance interpretation")
        + "</div>"
        '<section class="panel warning"><h2>Not comparable proof or approval</h2>'
        "<p>Runtime and cost are unverified source-reported observations. "
        "Different workloads, prices or sample sizes can invalidate a comparison. "
        "Summed cohort values are unnormalized; no budget or statistical "
        "significance is inferred. This file grants no authorization, consent, "
        "dispatch, release or source authentication.</p></section>"
        '<section class="panel"><h2>Resource changes by case</h2>'
        '<div class="table-scroll"><table><thead><tr>'
        + "".join('<th scope="col">' + _safe(h) + "</th>" for h in heads)
        + "</tr></thead><tbody>" + "".join(rows)
        + "</tbody></table></div></section>"
        '<section class="panel"><h2>Unnormalized cohort totals</h2>'
        + ("".join(aggregates) if aggregates else "<p>Input HOLD: no totals.</p>")
        + "</section><footer class='panel foot'>No original IDs, targets, paths "
        "or notes. Offline, no scripts or network. Never a HUMAN GO.</footer>"
        "</body></html>\n"
    )


def render_human_actions_json(result, *, cohort: bool = False,
                              scored: bool = False, focus: str = "all") -> str:
    """Machine-readable anonymous HUMAN questions, never an executable queue."""
    actions, selected = _select_human_actions(
        result, cohort=cohort, focus=focus,
    )
    payload = {
        "schema_version": 1,
        "report_type": (
            "scored_cohort" if scored else "cohort" if cohort else "single_case"
        ),
        "source_status": "REVIEW_ONLY" if result.status == "REVIEW_ONLY" else "HOLD",
        "input_admitted": bool(actions),
        "focus_filter": focus,
        "accepted_case_count": len(actions),
        "selected_case_count": len(selected),
        "notice": (
            "input_hold" if not actions else
            "no_matching_human_cases" if not selected else
            "human_review_only"
        ),
        "human_review_questions": [
            {
                "review_order": rank,
                "scenario_ordinal": ordinal,
                "human_review_group": group,
                "scope_policy_signal": scope,
                "source_adverse_metric_count": flags,
                "source_unknown_coverage": unknown,
                "suggested_human_question": question,
            }
            for rank, ordinal, group, flags, unknown, question, scope in selected
        ],
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_provenance_authenticated": False,
    }
    # No scenario IDs, paths, targets, identities, notes or freeform input data.
    return json_dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def render_human_actions_html(result, *, cohort: bool = False,
                              scored: bool = False, focus: str = "all") -> str:
    """Script-free printable HUMAN subset; no source IDs or metrics by case."""
    actions, selected = _select_human_actions(
        result, cohort=cohort, focus=focus,
    )
    kind = "Scored cohort" if scored else "Cohort" if cohort else "Single-case"
    status = "REVIEW_ONLY" if result.status == "REVIEW_ONLY" else "HOLD"
    pin = b64encode(
        sha256(_STYLES.encode("utf-8")).digest()
    ).decode("ascii")
    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; frame-src 'none'; script-src 'none'; "
        "style-src 'sha256-" + pin + "'"
    )
    rows = []
    for rank, ordinal, group, flags, unknown, question, _scope in selected:
        fields = (
            str(rank), "Scenario " + str(ordinal).zfill(2), group,
            str(flags), str(unknown), question,
        )
        rows.append("<tr>" + "".join("<td>" + _safe(v) + "</td>" for v in fields) + "</tr>")
    if not actions:
        rows.append(
            '<tr><td colspan="6">Input HOLD: no admitted case details. '
            'Ask the original owner to check input admission and consistency.</td></tr>'
        )
    elif not selected:
        rows.append(
            '<tr><td colspan="6">No HUMAN cases match this selected group. '
            'The original comparison is not cleared or approved.</td></tr>'
        )
    headings = (
        "Review order", "Anonymous case", "HUMAN group",
        "Source adverse flags", "Unknown coverage", "Suggested HUMAN question",
    )
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="'
        + escape(policy, quote=True) + '">'
        "<title>LightUp offline HUMAN actions — " + _safe(status) + "</title>"
        "<style>" + _STYLES + "</style></head><body>"
        "<header><p class='eyebrow'>LightUp · source-minimal private handoff</p>"
        "<h1>" + _safe(kind) + " HUMAN action selection</h1>"
        "<p><span class='badge'>" + _safe(status) + " · HUMAN REVIEW ONLY</span></p></header>"
        '<div class="grid" aria-label="Source and selection counts">'
        + _stat(len(actions), "All admitted anonymous cases")
        + _stat(len(selected), "Cases in this selection")
        + _stat(focus, "HUMAN focus filter")
        + "</div>"
        '<section class="panel warning"><h2>Not an authorization or release</h2>'
        "<p>These are unauthenticated, source-reported lab signals, not findings "
        "verified on a real system. Filtering hides other cases only in this "
        "view; it never clears them. No execution, consent, remediation proof "
        "or HUMAN GO is conveyed.</p>"
        "<p><strong>authorized=false · consent_verified=false · "
        "dispatch_allowed=false · release_allowed=false · "
        "source_provenance_authenticated=false</strong></p></section>"
        '<section class="panel"><h2>Selected HUMAN questions</h2>'
        '<p class="muted">Global review rank and original anonymous ordinal '
        "are retained. Only fixed question text and admitted aggregate numbers "
        "are shown; original IDs, source paths, network targets and notes "
        "are omitted.</p>"
        '<div class="table-scroll"><table><thead><tr>'
        + "".join('<th scope="col">' + _safe(h) + "</th>" for h in headings)
        + "</tr></thead><tbody>" + "".join(rows)
        + "</tbody></table></div></section>"
        "<footer class='panel foot'>Private offline file · unsigned and "
        "unverified. Review the original full comparison separately before "
        "taking any human action. No browser scripts or network.</footer>"
        "</body></html>\n"
    )
