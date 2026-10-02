from __future__ import annotations

import json
import unittest

from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import (
    EvaluationMetrics,
    ExpectedFinding,
    LabEvaluationHarness,
    LabIsolationError,
    LabScenario,
    assert_lab_target,
)


class LabEvalTest(unittest.TestCase):
    def test_lab_targets_are_loopback_or_private_only(self):
        self.assertEqual(assert_lab_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(assert_lab_target("http://localhost:8080"), "localhost")
        self.assertEqual(assert_lab_target("10.42.0.7"), "10.42.0.7")
        for bad in ("8.8.8.8", "example.com", "https://github.com", ""):
            with self.assertRaises((LabIsolationError, Exception)):
                assert_lab_target(bad)

    def test_scenario_rejects_real_targets(self):
        with self.assertRaises(LabIsolationError):
            LabScenario("s1", "bad", targets=("127.0.0.1", "8.8.8.8"))
        with self.assertRaises(ValueError):
            LabScenario("s2", "empty", targets=())

    def test_harness_produces_lab_only_contexts(self):
        scenario = LabScenario(
            "s1", "header lab", targets=("127.0.0.1",),
            expected_findings=(ExpectedFinding("f1", "Missing CSP", "web-baseline", "medium"),),
        )
        harness = LabEvaluationHarness(engine_version="test")
        context = harness.start_run(scenario)
        self.assertTrue(context.is_lab)
        self.assertIs(context.mode, AssessmentMode.LAB_AUTONOMOUS)
        self.assertIs(context.approved_risk, RiskLevel.DESTRUCTIVE_LAB_ONLY)
        self.assertIsNone(context.authorization)

    def test_record_schema_and_false_positive_rate(self):
        scenario = LabScenario("s1", "lab", targets=("127.0.0.1",))
        harness = LabEvaluationHarness(engine_version="test")
        context = harness.start_run(scenario)
        metrics = EvaluationMetrics(
            valid_findings=3, invalid_findings=1, missed_findings=2,
            coverage_assessed=4, coverage_unknown=6, evidence_quality=0.8,
            reproducibility=1.0, scope_violations=0, policy_violations=0,
            human_interventions=1, tool_calls=12, runtime_seconds=30.5,
            compute_cost_usd=0.42, remediation_quality=0.7, retest_correctness=1.0,
        )
        record = harness.record(scenario, context, metrics,
                                model_bindings=(("planner", "scripted/lab-model"),))
        payload = json.loads(record.to_json())
        self.assertEqual(payload["scenario_id"], "s1")
        self.assertAlmostEqual(payload["metrics"]["false_positive_rate"], 0.25)
        self.assertEqual(payload["metrics"]["coverage_unknown"], 6)
        self.assertEqual(harness.records, [record])

    def test_metrics_are_validated(self):
        scenario = LabScenario("s1", "lab", targets=("127.0.0.1",))
        harness = LabEvaluationHarness()
        context = harness.start_run(scenario)
        with self.assertRaises(ValueError):
            harness.record(scenario, context, EvaluationMetrics(evidence_quality=1.5))
        with self.assertRaises(ValueError):
            harness.record(scenario, context, EvaluationMetrics(scope_violations=-1))

    def test_non_lab_context_cannot_be_recorded(self):
        import dataclasses

        scenario = LabScenario("s1", "lab", targets=("127.0.0.1",))
        harness = LabEvaluationHarness()
        context = harness.start_run(scenario)
        forged = dataclasses.replace(context, is_lab=False)
        with self.assertRaises(LabIsolationError):
            harness.record(scenario, forged, EvaluationMetrics())


if __name__ == "__main__":
    unittest.main()
