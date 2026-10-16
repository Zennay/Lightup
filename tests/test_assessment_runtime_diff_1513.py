"""Assessment-runtime #1513: bounded offline comparison of genuine lab records."""
from __future__ import annotations

from dataclasses import replace
import math
import subprocess
import socket
import unittest
from unittest.mock import patch

from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations
from lightup.ai.orchestration import RunContext
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import EvaluationMetrics, EvaluationRecord


def sample(run_id="lab-run-a", metrics=None, scenario_id="fixture-1"):
    context = RunContext.for_lab(run_id, engagement_id=scenario_id)
    record = EvaluationRecord(
        record_id="record-" + run_id,
        scenario_id=scenario_id,
        run_id=run_id,
        engine_version="ci-model",
        model_bindings=(("planner", "scripted/lab"),),
        metrics=metrics or EvaluationMetrics(
            valid_findings=3, invalid_findings=0, missed_findings=1,
            coverage_assessed=2, coverage_unknown=2, evidence_quality=0.8,
            reproducibility=0.75, remediation_quality=0.7,
            retest_correctness=0.9, runtime_seconds=1.5,
            compute_cost_usd=0.25, tool_calls=3,
        ),
        created_at="2026-10-16T21:00:00+00:00",
    )
    return record, context


def pair(base_metrics=None, next_metrics=None):
    a, ca = sample(metrics=base_metrics)
    b, cb = sample("lab-run-b", next_metrics)
    return a, b, ca, cb


class AssessmentRuntimeDiffTests(unittest.TestCase):
    def test_identical_lab_records_remain_review_only_never_authorized(self):
        result = compare_lab_evaluations(*pair())
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.regressions, ())
        self.assertEqual(len(result.changes), 15)
        self.assertTrue(all(change.delta == 0 for change in result.changes))
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, field), False)
        with self.assertRaises(Exception):
            result.authorized = True

    def test_multi_metric_degradation_holds_with_stable_diffs(self):
        a, b, ca, cb = pair()
        b = replace(b, metrics=replace(
            b.metrics, valid_findings=2, invalid_findings=1,
            coverage_assessed=1, policy_violations=1, evidence_quality=0.7,
        ))
        result = compare_lab_evaluations(a, b, ca, cb)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.regressions, (
            "valid_findings", "invalid_findings", "coverage_assessed",
            "policy_violations", "evidence_quality",
        ))
        self.assertEqual(next(c.delta for c in result.changes if c.name == "valid_findings"), -1)

    def test_improvements_do_not_raise_authority(self):
        a, b, ca, cb = pair()
        b = replace(b, metrics=replace(
            b.metrics, valid_findings=4, missed_findings=0,
            reproducibility=0.9, runtime_seconds=0.5,
        ))
        result = compare_lab_evaluations(a, b, ca, cb)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertIs(result.release_allowed, False)

    def test_runtime_and_cost_deltas_are_informational_not_release_clearance(self):
        a, b, ca, cb = pair()
        b = replace(b, metrics=replace(b.metrics, runtime_seconds=10.0, compute_cost_usd=20.0))
        result = compare_lab_evaluations(a, b, ca, cb)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertFalse(any(change.regression for change in result.changes))
        self.assertEqual(next(c.delta for c in result.changes if c.name == "runtime_seconds"), 8.5)

    def test_cross_scenario_and_non_lab_records_hold_without_details(self):
        a, b, ca, cb = pair()
        cases = [
            (a, replace(b, scenario_id="fixture-2"), ca, cb),
            (a, b, ca, replace(cb, is_lab=False)),
            (a, b, ca, replace(cb, mode=AssessmentMode.PASSIVE_DISCOVERY)),
            (a, b, ca, replace(cb, approved_risk=RiskLevel.PASSIVE)),
            (a, b, ca, replace(cb, engagement_id="other")),
            (a, replace(b, run_id="wrong"), ca, cb),
            (a, replace(b, model_bindings=(("planner", "scripted/lab"), ("weird", 4))), ca, cb),
            (a, replace(b, record_id=""), ca, cb),
            (a, replace(b, created_at=""), ca, cb),
            (a, replace(b, notes=5), ca, cb),
        ]
        for values in cases:
            with self.subTest(values=repr(values)[:90]):
                result = compare_lab_evaluations(*values)
                self.assertEqual((result.status, result.changes, result.regressions),
                                 ("HOLD", (), ()))
                self.assertIs(result.dispatch_allowed, False)

    def test_fractional_boolean_negative_and_nonfinite_counts_hold(self):
        a, b, ca, cb = pair()
        for value in (-1, True, 1.5, "3", None, 1_000_000_001):
            for field in ("valid_findings", "coverage_unknown", "tool_calls"):
                with self.subTest(field=field, value=value):
                    fake = replace(b, metrics=replace(b.metrics, **{field: value}))
                    self.assertEqual(compare_lab_evaluations(a, fake, ca, cb).status, "HOLD")

    def test_invalid_scores_and_performance_hold(self):
        a, b, ca, cb = pair()
        for field in ("evidence_quality", "reproducibility",
                      "remediation_quality", "retest_correctness"):
            for value in (True, -0.1, 1.001, float("nan"), float("inf"), "0.5"):
                with self.subTest(field=field, value=value):
                    fake = replace(b, metrics=replace(b.metrics, **{field: value}))
                    self.assertEqual(compare_lab_evaluations(a, fake, ca, cb).status, "HOLD")
        for field in ("runtime_seconds", "compute_cost_usd"):
            for value in (True, -0.01, float("nan"), float("-inf"), None):
                fake = replace(b, metrics=replace(b.metrics, **{field: value}))
                self.assertEqual(compare_lab_evaluations(a, fake, ca, cb).status, "HOLD")

    def test_wrong_builtin_types_cannot_fake_valid_records(self):
        a, b, ca, cb = pair()
        for values in (
            (object(), b, ca, cb),
            (a, b, object(), cb),
            (a, replace(b, metrics=object()), ca, cb),
            (a, replace(b, model_bindings=[("planner", "scripted/lab")]), ca, cb),
            (a, replace(b, scenario_id=" fixture-1"), ca, cb),
        ):
            self.assertEqual(compare_lab_evaluations(*values).status, "HOLD")

    def test_inputs_are_unchanged_and_no_external_execution(self):
        original = pair()
        with patch.object(socket, "socket", side_effect=AssertionError("network attempted")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process attempted")):
            result = compare_lab_evaluations(*original)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(original, pair())


if __name__ == "__main__":
    unittest.main()
