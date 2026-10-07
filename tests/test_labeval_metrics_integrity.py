from __future__ import annotations

import math
import unittest

from lightup.labeval import EvaluationMetrics, LabEvaluationHarness, LabScenario


class EvaluationMetricsIntegrityTest(unittest.TestCase):
    def test_canonical_evidence_and_remediation_metrics_remain_valid(self):
        metrics = EvaluationMetrics(
            valid_findings=3,
            invalid_findings=1,
            missed_findings=2,
            coverage_assessed=4,
            coverage_unknown=6,
            evidence_quality=0.8,
            reproducibility=1.0,
            scope_violations=0,
            policy_violations=0,
            human_interventions=1,
            tool_calls=12,
            runtime_seconds=30.5,
            compute_cost_usd=0.42,
            remediation_quality=0.7,
            retest_correctness=1.0,
        )

        metrics.validate()

    def test_quality_scores_reject_boolean_values(self):
        for field in (
            "evidence_quality",
            "reproducibility",
            "remediation_quality",
            "retest_correctness",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    EvaluationMetrics(**{field: True}).validate()

    def test_counter_metrics_require_exact_non_negative_integers(self):
        for field in (
            "valid_findings",
            "invalid_findings",
            "missed_findings",
            "coverage_assessed",
            "coverage_unknown",
            "scope_violations",
            "policy_violations",
            "human_interventions",
            "tool_calls",
        ):
            for invalid in (True, 0.5):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(ValueError):
                        EvaluationMetrics(**{field: invalid}).validate()

    def test_runtime_and_cost_require_finite_non_negative_numbers(self):
        for field in ("runtime_seconds", "compute_cost_usd"):
            for invalid in (True, -0.01, math.inf, -math.inf, math.nan):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(ValueError):
                        EvaluationMetrics(**{field: invalid}).validate()

    def test_invalid_metrics_fail_before_evaluation_record_is_appended(self):
        scenario = LabScenario("metrics-integrity", "metrics integrity", ("127.0.0.1",))

        cases = (
            EvaluationMetrics(remediation_quality=True),
            EvaluationMetrics(valid_findings=0.5),
            EvaluationMetrics(runtime_seconds=-1.0),
            EvaluationMetrics(compute_cost_usd=math.inf),
        )
        for metrics in cases:
            with self.subTest(metrics=metrics):
                harness = LabEvaluationHarness(engine_version="test")
                context = harness.start_run(scenario)

                with self.assertRaises(ValueError):
                    harness.record(scenario, context, metrics)

                self.assertEqual(harness.records, [])


if __name__ == "__main__":
    unittest.main()
