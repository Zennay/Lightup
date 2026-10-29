"""Compare two finished, independently verified fixed-loopback lab score bundles.

No target, worker, grant, model, external network or write is permitted. An
aggregate result is not proof of original evidence or real-world authority.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .lab_score_inspect import inspect_score_run
from .lab_score_suite import _EXPECTED_FINDINGS

SCHEMA = "lightup.lab-score-compare.v1"
# No runtime_seconds: duration varies even when fixture scoring is identical.
_SCORE_FIELDS = (
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "evidence_quality",
    "reproducibility", "scope_violations", "policy_violations",
)


def compare_score_runs(baseline_dir: str | Path, candidate_dir: str | Path) -> dict[str, Any]:
    baseline = inspect_score_run(baseline_dir, include_metrics=True)
    candidate = inspect_score_run(candidate_dir, include_metrics=True)
    # Both inputs were opened and validated without following links. Reject
    # self-comparison before presenting a false independent repeat.
    if os.path.samefile(baseline_dir, candidate_dir):
        raise ValueError("baseline and candidate are the same saved run")
    comparison: dict[str, dict[str, Any]] = {}
    repeat_independent = True
    score_stable = True
    for name in _EXPECTED_FINDINGS:
        before = baseline["capabilities"][name]
        after = candidate["capabilities"][name]
        duplicate = before["record_sha256"] == after["record_sha256"]
        deltas = {
            metric: {"baseline": before["score_metrics"][metric],
                     "candidate": after["score_metrics"][metric]}
            for metric in _SCORE_FIELDS
            if before["score_metrics"][metric] != after["score_metrics"][metric]
        }
        repeat_independent &= not duplicate
        score_stable &= not deltas
        comparison[name] = {
            "distinct_evaluation": not duplicate,
            "baseline_evidence_count": before["evidence_count"],
            "candidate_evidence_count": after["evidence_count"],
            "changed_metrics": deltas,
        }
    passed = bool(score_stable and repeat_independent)
    return {
        "schema": SCHEMA,
        "passed": passed,
        "independent_evaluations": bool(repeat_independent),
        "score_stable": bool(score_stable),
        "capabilities": comparison,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-compare",
        description="Compare two saved, verified private loopback score runs without replay.",
    )
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--candidate-dir", required=True)
    args = parser.parse_args(argv)
    try:
        report = compare_score_runs(args.baseline_dir, args.candidate_dir)
    except Exception as exc:
        print(json.dumps({
            "schema": SCHEMA, "passed": False, "error_type": type(exc).__name__,
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
