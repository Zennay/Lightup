"""Integration of #1513 review-only diffs with the actual LightUp lab harness.

No worker registrations, network connections, state database or scanning.
"""
from __future__ import annotations

from dataclasses import replace
import unittest

from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations
from lightup.ai.assessment_runtime_cohort_1513 import compare_lab_cohorts
from lightup.labeval import EvaluationMetrics, LabEvaluationHarness, LabScenario


def real_result(scenario, version, **metrics):
    harness = LabEvaluationHarness(engine_version=version)
    context = harness.start_run(scenario)
    record = harness.record(
        scenario, context,
        EvaluationMetrics(valid_findings=3, coverage_assessed=2,
                          evidence_quality=0.8, reproducibility=0.9, **metrics),
        model_bindings=(("planner", "scripted/lab"),),
    )
    assert len(harness.records) == 1
    return record, context


class RealHarnessCompatTests(unittest.TestCase):
    def test_comparison_consumes_genuine_lab_evaluation_record(self):
        scenario = LabScenario("real-harness-1", "loopback only", targets=("127.0.0.1",))
        baseline, baseline_context = real_result(scenario, "baseline")
        candidate, candidate_context = real_result(scenario, "candidate")
        result = compare_lab_evaluations(
            baseline, candidate, baseline_context, candidate_context,
        )
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.regressions, ())
        self.assertFalse(result.dispatch_allowed)

    def test_genuine_harness_regression_is_hold_not_a_pass(self):
        scenario = LabScenario("real-harness-2", "loopback only", targets=("127.0.0.1",))
        a, ca = real_result(scenario, "baseline")
        b, cb = real_result(scenario, "candidate")
        b = replace(b, metrics=replace(b.metrics, valid_findings=2))
        result = compare_lab_evaluations(a, b, ca, cb)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.regressions, ("valid_findings",))
        self.assertFalse(result.release_allowed)

    def test_atomic_cohort_of_real_harness_records(self):
        scenarios = (
            LabScenario("lab-a", "A", targets=("127.0.0.1",)),
            LabScenario("lab-b", "B", targets=("127.0.0.1",)),
        )
        before = tuple(real_result(s, "baseline") for s in scenarios)
        after = tuple(real_result(s, "candidate") for s in reversed(scenarios))
        result = compare_lab_cohorts(before, after)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(tuple(s for s, _ in result.comparisons), ("lab-a", "lab-b"))

    def test_huge_ints_return_hold_without_arithmetic_overflow(self):
        scenario = LabScenario("huge-int", "loopback", targets=("127.0.0.1",))
        a, ca = real_result(scenario, "baseline")
        b, cb = real_result(scenario, "candidate")
        for name in ("evidence_quality", "retest_correctness", "runtime_seconds", "compute_cost_usd"):
            with self.subTest(field=name):
                invalid = replace(b, metrics=replace(b.metrics, **{name: 10 ** 600}))
                result = compare_lab_evaluations(a, invalid, ca, cb)
                self.assertEqual((result.status, result.changes), ("HOLD", ()))
                self.assertFalse(result.authorized)


if __name__ == "__main__":
    unittest.main()
