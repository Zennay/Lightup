from __future__ import annotations

import dataclasses
import unittest

from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import EvaluationMetrics, LabEvaluationHarness, LabIsolationError, LabScenario


class LabEvaluationContextBindingTests(unittest.TestCase):
    def setUp(self):
        self.scenario = LabScenario("scenario-a", "lab", targets=("127.0.0.1",))
        self.harness = LabEvaluationHarness(engine_version="test")

    def test_harness_minted_context_records_successfully(self):
        context = self.harness.start_run(self.scenario)

        record = self.harness.record(
            self.scenario,
            context,
            EvaluationMetrics(),
        )

        self.assertEqual(record.run_id, context.run_id)
        self.assertEqual(record.scenario_id, self.scenario.scenario_id)

    def test_context_from_another_harness_is_rejected(self):
        foreign = LabEvaluationHarness(engine_version="test").start_run(self.scenario)

        with self.assertRaisesRegex(LabIsolationError, "created by this harness"):
            self.harness.record(self.scenario, foreign, EvaluationMetrics())

    def test_type_consistent_but_semantically_forged_mode_is_rejected(self):
        context = self.harness.start_run(self.scenario)
        forged = dataclasses.replace(
            context,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            is_lab=True,
        )

        with self.assertRaisesRegex(LabIsolationError, "no longer matches"):
            self.harness.record(self.scenario, forged, EvaluationMetrics())

    def test_forged_risk_ceiling_is_rejected(self):
        context = self.harness.start_run(self.scenario)
        forged = dataclasses.replace(context, approved_risk=RiskLevel.PASSIVE)

        with self.assertRaisesRegex(LabIsolationError, "no longer matches"):
            self.harness.record(self.scenario, forged, EvaluationMetrics())

    def test_context_cannot_be_reused_for_another_scenario(self):
        context = self.harness.start_run(self.scenario)
        other = LabScenario("scenario-b", "other lab", targets=("127.0.0.1",))

        with self.assertRaisesRegex(LabIsolationError, "another lab scenario"):
            self.harness.record(other, context, EvaluationMetrics())


if __name__ == "__main__":
    unittest.main()
