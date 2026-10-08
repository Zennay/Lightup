"""Fail-closed acceptance for malformed PASSIVE_PUBLIC risk identity; no network I/O."""
import os
import sys
import unittest
from enum import IntEnum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ForeignRisk(IntEnum):
    PASSIVE = 1


class PassiveRiskIdentityAcceptance(unittest.TestCase):
    def test_canonical_passive_control(self):
        request = ExecutionRequest(InteractionKind.PASSIVE_PUBLIC, "example.test", "public-metadata", RiskLevel.PASSIVE)
        self.assertTrue(ExecutionPolicy().decide(request).allowed)

    def test_noncanonical_passive_risks_fail_closed(self):
        for value in (True, 0, 1, -1, ForeignRisk.PASSIVE):
            with self.subTest(value=repr(value)):
                request = ExecutionRequest(InteractionKind.PASSIVE_PUBLIC, "example.test", "public-metadata", value)
                decision = ExecutionPolicy().decide(request)
                self.assertFalse(decision.allowed, "noncanonical risk must not enable passive discovery")


if __name__ == "__main__":
    unittest.main()
