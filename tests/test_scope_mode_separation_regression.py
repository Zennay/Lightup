"""Offline mode-separation regression: no grants or targets are contacted.

Run with PYTHONPATH=src python -m unittest tests.test_scope_mode_separation_regression
"""
import unittest

from lightup.execution_policy import (
    ExecutionPolicy, ExecutionRequest, InteractionKind,
)
from lightup.engagements import RiskLevel


class ModeSeparationRegression(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def request(self, mode, risk, *, lab=False):
        return ExecutionRequest(
            interaction=mode, asset="example.invalid",
            capability_id="offline-contract", requested_risk=risk,
            is_lab=lab,
        )

    def test_analysis_can_only_request_analysis_risk(self):
        for risk in (RiskLevel.PASSIVE, RiskLevel.STANDARD, RiskLevel.DESTRUCTIVE_LAB_ONLY):
            with self.subTest(risk=risk):
                self.assertFalse(self.policy.decide(self.request(InteractionKind.ANALYSIS, risk)).allowed)
        self.assertTrue(self.policy.decide(self.request(
            InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
        )).allowed)

    def test_passive_public_cannot_upgrade_to_active(self):
        for risk in (RiskLevel.STANDARD, RiskLevel.DESTRUCTIVE_LAB_ONLY):
            with self.subTest(risk=risk):
                self.assertFalse(self.policy.decide(self.request(InteractionKind.PASSIVE_PUBLIC, risk)).allowed)
        self.assertTrue(self.policy.decide(self.request(
            InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE,
        )).allowed)

    def test_lab_active_requires_explicit_lab_flag(self):
        for lab in (False, True):
            with self.subTest(lab=lab):
                verdict = self.policy.decide(self.request(
                    InteractionKind.LAB_ACTIVE, RiskLevel.STANDARD, lab=lab,
                ))
                self.assertEqual(verdict.allowed, lab)

    def test_target_active_never_uses_lab_flag_as_authorization(self):
        for lab in (False, True):
            with self.subTest(lab=lab):
                verdict = self.policy.decide(self.request(
                    InteractionKind.TARGET_ACTIVE, RiskLevel.STANDARD, lab=lab,
                ))
                self.assertFalse(verdict.allowed)


if __name__ == "__main__":
    unittest.main()
