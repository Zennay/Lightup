"""Read-only atomic cohort comparison over two explicit local JSON arrays.

Usage: python scripts/assessment_runtime_compare_cohort_cli_1513.py [--format json|text|html|csv|actions-csv|actions-html|actions-json|efficiency-json|efficiency-html|review-json|review-bundle-json|review-bundle-html] [--focus all|scope|adverse|unknown|source] [--expected-baseline-sha256 HEX --expected-candidate-sha256 HEX] base.json next.json
Focus selectors overlap when a case has multiple source-reported signals.
Source focus covers every admitted unauthenticated case; focus questions match the selected signal.
Each file is an array of 1..64 single-case JSON envelopes.
Never a release or authorization gate: exits 2 REVIEW_ONLY / 3 HOLD only.
"""
from __future__ import annotations

import json
import sys

from assessment_runtime_cli_options_1513 import parse_offline_cli_args

from assessment_runtime_report_html_1513 import (
    render_comparison_html, render_comparison_csv,
    render_human_actions_csv, render_human_actions_html,
    render_human_actions_json, render_efficiency_json, render_efficiency_html,
    render_metric_review_json, render_review_bundle_json,
    render_review_bundle_html,
)

from assessment_runtime_compare_cli_1513 import (
    _read_json, _parse_case_document, _split_expected_pair_hashes,
)
from lightup.ai.assessment_runtime_cohort_1513 import (
    LabCohortComparison, compare_lab_cohorts,
)

COHORT_BYTES = 262_144


def _load(path, *, expected_sha256=None):
    items = _read_json(
        path, maximum_bytes=COHORT_BYTES, expected_sha256=expected_sha256,
    )
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
    clean_args, expected, bad_hash_flags = _split_expected_pair_hashes(
        sys.argv[1:] if argv is None else argv
    )
    output_format, focus_filter, positional, malformed = parse_offline_cli_args(
        clean_args
    )
    review = LabCohortComparison("HOLD")
    if len(positional) == 2 and not malformed and not bad_hash_flags:
        try:
            before = _load(
                positional[0],
                expected_sha256=expected.get("--expected-baseline-sha256"),
            )
            after = _load(
                positional[1],
                expected_sha256=expected.get("--expected-candidate-sha256"),
            )
            review = compare_lab_cohorts(before, after)
        except (OSError, ValueError, KeyError, TypeError, OverflowError,
                UnicodeError, RecursionError):
            pass
    if output_format == "text":
        print(_display_text(review))
    elif output_format == "html":
        print(render_comparison_html(review, cohort=True, scored=False), end="")
    elif output_format == "review-bundle-html":
        print(render_review_bundle_html(review, cohort=True, scored=False), end="")
    elif output_format == "review-bundle-json":
        print(render_review_bundle_json(review, cohort=True, scored=False), end="")
    elif output_format == "review-json":
        print(render_metric_review_json(review, cohort=True, scored=False), end="")
    elif output_format == "efficiency-json":
        print(render_efficiency_json(review, cohort=True, scored=False), end="")
    elif output_format == "efficiency-html":
        print(render_efficiency_html(review, cohort=True, scored=False), end="")
    elif output_format == "actions-json":
        print(render_human_actions_json(review, cohort=True, scored=False, focus=focus_filter), end="")
    elif output_format == "actions-html":
        print(render_human_actions_html(review, cohort=True, scored=False, focus=focus_filter), end="")
    elif output_format == "actions-csv":
        print(render_human_actions_csv(review, cohort=True, scored=False, focus=focus_filter), end="")
    elif output_format == "csv":
        print(render_comparison_csv(review, cohort=True, scored=False), end="")
    else:
        print(json.dumps(_display(review), sort_keys=True, separators=(",", ":")))
    return 2 if review.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
