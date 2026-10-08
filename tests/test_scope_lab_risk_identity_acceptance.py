"""Offline acceptance: lab mode must never interpret foreign risk identities as authorization.

Expected RED against the current policy. The source-owner PR must implement the fix.
"""
import os
import sys
import unittest
from enum import IntEnum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ForeignRisk(IntEnum):
    PASSIVE = 1


class LabRiskIdentityAcceptance(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def decide(self, risk, *, is_lab=True):
        return self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset="synthetic-local-lab",
                capability_id="inert-offline-test",
                requested_risk=risk,
                is_lab=is_lab,
            )
        )

    def test_canonical_lab_risk_remains_permitted(self):
        self.assertTrue(self.decide(RiskLevel.LOW_IMPACT).allowed)

    def test_non_lab_target_remains_denied(self):
        self.assertFalse(self.decide(RiskLevel.LOW_IMPACT, is_lab=False).allowed)

    def test_foreign_risk_identities_fail_closed(self):
        invalid = (True, False, 0, 1, -1, 999, "standard", None, ForeignRisk.PASSIVE)
        for risk in invalid:
            with self.subTest(risk=repr(risk)):
                result = self.decide(risk)
                self.assertFalse(result.allowed, f"foreign risk identity {risk!r} was accepted")

    def test_no_authorization_is_inferred_from_invalid_risk(self):
        # Even a truthy lab flag must not turn a malformed risk into a valid risk identity.
        self.assertFalse(self.decide(object()).allowed)


if __name__ == "__main__":
    unittest.main()
