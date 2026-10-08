"""Offline acceptance: LAB_ACTIVE risk identity must be canonical.

Expected RED until the ExecutionPolicy source owner integrates this guard.
No network, target, handler, or scanner is invoked by these tests.
"""
import unittest
from enum import IntEnum

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ForeignRisk(IntEnum):
    ANALYSIS_ONLY = 0
    DESTRUCTIVE = 5


class LabRiskIdentityAcceptanceTests(unittest.TestCase):
    def request(self, risk):
        return ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="offline-lab.invalid",
            capability_id="offline-reference-only",
            requested_risk=risk,
            is_lab=True,
        )

    def test_exact_canonical_lab_risk_retains_eligibility(self):
        decision = ExecutionPolicy().decide(self.request(RiskLevel.DESTRUCTIVE_LAB_ONLY))
        self.assertTrue(decision.allowed)

    def test_noncanonical_lab_risk_is_denied(self):
        for risk in (True, False, 0, 5, -1, 99, ForeignRisk.ANALYSIS_ONLY,
                     ForeignRisk.DESTRUCTIVE, "5", None, object()):
            with self.subTest(risk=repr(risk)):
                decision = ExecutionPolicy().decide(self.request(risk))
                self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
