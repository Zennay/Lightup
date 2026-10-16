"""Read-only atomic cohort comparison over two explicit local JSON arrays.

Usage: python scripts/assessment_runtime_compare_cohort_cli_1513.py base.json next.json
Each file is an array of 1..64 single-case JSON envelopes.
Never a release or authorization gate: exits 2 REVIEW_ONLY / 3 HOLD only.
"""
from __future__ import annotations

import json
import sys

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


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    review = LabCohortComparison("HOLD")
    if len(args) == 2:
        try:
            before = _load(args[0])
            after = _load(args[1])
            review = compare_lab_cohorts(before, after)
        except (OSError, ValueError, KeyError, TypeError, OverflowError,
                UnicodeError, RecursionError):
            pass
    print(json.dumps(_display(review), sort_keys=True, separators=(",", ":")))
    return 2 if review.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
