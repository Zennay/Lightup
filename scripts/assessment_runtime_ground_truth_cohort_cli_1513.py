"""Offline scored lab cohort review: 2 REVIEW_ONLY / 3 HOLD, NEVER a grant.

Usage: python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py [--format json|text|html|csv|actions-csv|actions-html|actions-json|efficiency-json|efficiency-html] [--focus all|scope|adverse|unknown|source] old.json new.json
Focus selectors overlap when a case has multiple source-reported signals.
Only two explicitly supplied local files are read, never a network endpoint.
"""
from __future__ import annotations

import json
import sys

from assessment_runtime_cli_options_1513 import parse_offline_cli_args

from assessment_runtime_report_html_1513 import (
    render_comparison_html, render_comparison_csv,
    render_human_actions_csv, render_human_actions_html,
    render_human_actions_json, render_efficiency_json, render_efficiency_html,
)

from assessment_runtime_compare_cli_1513 import _parse_case_document, _read_json
from assessment_runtime_compare_cohort_cli_1513 import _display, COHORT_BYTES
from lightup.ai.assessment_runtime_cohort_1513 import LabCohortComparison
from lightup.ai.assessment_runtime_ground_truth_cohort_1513 import compare_ground_truthed_lab_cohorts
from lightup.labeval import ExpectedFinding, LabScenario

SCENARIO_KEYS = frozenset(('scenario_id', 'name', 'description', 'targets', 'endpoints', 'expected_findings'))
FINDING_KEYS = frozenset(('identifier', 'title', 'capability_id', 'severity'))


def _parse_scored_case(packet):
    if type(packet) is not dict or set(packet) != {'scenario', 'record', 'context'}:
        raise ValueError('invalid scored case schema')
    data = packet['scenario']
    if type(data) is not dict or set(data) != SCENARIO_KEYS:
        raise ValueError('invalid scenario schema')
    raw_targets, raw_endpoints, findings = (
        data['targets'], data['endpoints'], data['expected_findings'],
    )
    if (type(raw_targets) is not list or not 1 <= len(raw_targets) <= 64
            or type(raw_endpoints) is not list or len(raw_targets) != len(raw_endpoints)
            or type(findings) is not list or len(findings) > 1024):
        raise ValueError('invalid scenario lists')
    if any(type(target) is not str for target in raw_targets + raw_endpoints):
        raise ValueError('invalid target types')
    if any(type(item) is not dict or set(item) != FINDING_KEYS
           or any(type(value) is not str for value in item.values()) for item in findings):
        raise ValueError('invalid finding types')
    # Construction applies LightUp's existing *local* lab-only target policy;
    # the post-construction review independently checks every asset binding.
    scenario = LabScenario(
        scenario_id=data['scenario_id'], name=data['name'],
        description=data['description'], targets=tuple(raw_targets),
        expected_findings=tuple(ExpectedFinding(**item) for item in findings),
    )
    if scenario.endpoints != tuple(raw_endpoints):
        raise ValueError('mismatched original endpoints')
    record, context = _parse_case_document({
        'record': packet['record'], 'context': packet['context'],
    })
    return scenario, record, context


def _load(path):
    packets = _read_json(path, maximum_bytes=COHORT_BYTES)
    if type(packets) is not list or not 1 <= len(packets) <= 64:
        raise ValueError('invalid scored cohort shape')
    return tuple(_parse_scored_case(packet) for packet in packets)


def _display_text(review: LabCohortComparison) -> str:
    """Render a privacy-minimal scored-cohort summary without source identifiers."""
    lines = [
        "LightUp assessment-runtime scored cohort comparison",
        f"Status: {review.status}",
        f"Scenarios compared: {len(review.comparisons)}",
        f"Scenarios with source-reported adverse flags: {len(review.regressed_scenarios)}",
        "Input mode: explicit local files only; source provenance and chronology are unauthenticated.",
        "REVIEW_ONLY is not remediation proof, consent or release approval.",
    ]
    if not review.comparisons:
        lines.append(
            "No scenario details emitted; input admission, source ground truth or "
            "cohort consistency did not permit a complete comparison."
        )
    else:
        for ordinal, (_scenario_id, comparison) in enumerate(review.comparisons, 1):
            adverse = ", ".join(comparison.regressions) if comparison.regressions else "none reported"
            lines.append(
                f"Scenario {ordinal:02d}: {comparison.status}; "
                f"source-reported adverse metrics: {adverse}"
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
    output_format, focus_filter, positional, malformed = parse_offline_cli_args(
        sys.argv[1:] if argv is None else argv
    )
    review = LabCohortComparison('HOLD')
    if len(positional) == 2 and not malformed:
        try:
            review = compare_ground_truthed_lab_cohorts(
                _load(positional[0]), _load(positional[1]),
            )
        except (
            OSError, ValueError, KeyError, TypeError, OverflowError,
            UnicodeError, RecursionError, PermissionError,
        ):
            pass
    if output_format == "text":
        print(_display_text(review))
    elif output_format == "html":
        print(render_comparison_html(review, cohort=True, scored=True), end="")
    elif output_format == "efficiency-json":
        print(render_efficiency_json(review, cohort=True, scored=True), end="")
    elif output_format == "efficiency-html":
        print(render_efficiency_html(review, cohort=True, scored=True), end="")
    elif output_format == "actions-json":
        print(render_human_actions_json(review, cohort=True, scored=True, focus=focus_filter), end="")
    elif output_format == "actions-html":
        print(render_human_actions_html(review, cohort=True, scored=True, focus=focus_filter), end="")
    elif output_format == "actions-csv":
        print(render_human_actions_csv(review, cohort=True, scored=True, focus=focus_filter), end="")
    elif output_format == "csv":
        print(render_comparison_csv(review, cohort=True, scored=True), end="")
    else:
        print(json.dumps(_display(review), sort_keys=True, separators=(',', ':')))
    return 2 if review.status == 'REVIEW_ONLY' else 3


if __name__ == '__main__':
    raise SystemExit(main())
