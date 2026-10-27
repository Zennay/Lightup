"""Read-only atomic cohort comparison over two explicit local JSON arrays.

Usage: python scripts/assessment_runtime_compare_cohort_cli_1513.py [--format json|text|html|csv|actions-csv] base.json next.json
Each file is an array of 1..64 single-case JSON envelopes.
Never a release or authorization gate: exits 2 REVIEW_ONLY / 3 HOLD only.
"""
from __future__ import annotations

import json
import sys

from assessment_runtime_report_html_1513 import (
    render_comparison_html, render_comparison_csv, render_human_actions_csv,
)

from assessment_runtime_compare_cli_1513 import _read_json, _parse_case_document
from lightup.ai.assessment_runtime_cohort_1513 import (
    LabCohortComparison, compare_lab_cohorts,
)

COHORT_BYTES = 262_144


def _load(path):
    items = _read_json(path, maximum_bytes=COHORT_BYTES)
    if type(items) is not list or not 1 <= len(items) <= 64:
        raise ValueError("bad cohort envelope")
    return tuple(_parse_case_document(item) for item in items)


def _display(review):
    return {
        "status": review.status,
        "regressed_scenarios": list(review.regressed_scenarios),
        "comparisons": [
            {
                "scenario_id": scenario,
                "status": comparison.status,
                "regressions": list(comparison.regressions),
                "changes": [
                    {"name": change.name, "baseline": change.baseline,
                     "candidate": change.candidate, "delta": change.delta,
                     "regression": change.regression}
                    for change in comparison.changes
                ],
            }
            for scenario, comparison in review.comparisons
        ],
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }


def _display_text(review: LabCohortComparison) -> str:
    """Render a privacy-minimal local summary without source scenario identifiers."""
    lines = [
        "LightUp assessment-runtime cohort comparison",
        f"Status: {review.status}",
        f"Scenarios compared: {len(review.comparisons)}",
        f"Scenarios with source-reported adverse flags: {len(review.regressed_scenarios)}",
        "Input mode: local files only; source provenance and chronology are unauthenticated.",
        "REVIEW_ONLY is not a pass, remediation proof, consent or release approval.",
    ]
    if not review.comparisons:
        lines.append(
            "No scenario details emitted; input admission or cohort consistency "
            "did not permit a complete comparison."
        )
    else:
        for ordinal, (_scenario_id, comparison) in enumerate(review.comparisons, 1):
            regressions = ", ".join(comparison.regressions) if comparison.regressions else "none reported"
            lines.append(
                f"Scenario {ordinal:02d}: {comparison.status}; "
                f"source-reported adverse metrics: {regressions}"
            )
            for change in comparison.changes:
                flag = "FLAGGED" if change.regression else "not flagged"
                lines.append(
                    f"  {change.name}: baseline={change.baseline} "
                    f"candidate={change.candidate} delta={change.delta} [{flag}]"
                )
    lines.extend([
        "Authority: authorized=false; consent_verified=false; "
        "dispatch_allowed=false; release_allowed=false.",
        "No target, network, handler, grant, state write or deployment was used.",
    ])
    return "\n".join(lines)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    output_format = "json"
    format_seen = False
    malformed = False
    positional = []
    index = 0
    while index < len(args):
        item = args[index]
        if item == "--format":
            if format_seen or index + 1 >= len(args) or args[index + 1] not in ("json", "text", "html", "csv", "actions-csv"):
                malformed = True
                index += 2 if index + 1 < len(args) else 1
            else:
                output_format = args[index + 1]
                format_seen = True
                index += 2
        elif item.startswith("--"):
            malformed = True
            index += 1
        else:
            positional.append(item)
            index += 1

    review = LabCohortComparison("HOLD")
    if len(positional) == 2 and not malformed:
        try:
            before = _load(positional[0])
            after = _load(positional[1])
            review = compare_lab_cohorts(before, after)
        except (OSError, ValueError, KeyError, TypeError, OverflowError,
                UnicodeError, RecursionError):
            pass
    if output_format == "text":
        print(_display_text(review))
    elif output_format == "html":
        print(render_comparison_html(review, cohort=True, scored=False), end="")
    elif output_format == "actions-csv":
        print(render_human_actions_csv(review, cohort=True, scored=False), end="")
    elif output_format == "csv":
        print(render_comparison_csv(review, cohort=True, scored=False), end="")
    else:
        print(json.dumps(_display(review), sort_keys=True, separators=(",", ":")))
    return 2 if review.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
