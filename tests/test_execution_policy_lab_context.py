import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ExecutionPolicyLabContextTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def test_truthy_string_cannot_satisfy_lab_context(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset="isolated-lab",
                capability_id="wireless-lab",
                requested_risk=RiskLevel.STANDARD,
                is_lab="false",  # type: ignore[arg-type]
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "lab context marker must be a bool")

    def test_integer_cannot_satisfy_lab_context(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset="isolated-lab",
                capability_id="wireless-lab",
                requested_risk=RiskLevel.STANDARD,
                is_lab=1,  # type: ignore[arg-type]
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "lab context marker must be a bool")

    def test_exact_false_still_denies_lab_active(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset="isolated-lab",
                capability_id="wireless-lab",
                requested_risk=RiskLevel.STANDARD,
                is_lab=False,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "lab execution requires a lab target")

    def test_exact_true_reaches_lab_active_policy(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset="isolated-lab",
                capability_id="wireless-lab",
                requested_risk=RiskLevel.STANDARD,
                is_lab=True,
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "isolated lab execution")

    def test_non_boolean_marker_fails_before_passive_policy(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.PASSIVE_PUBLIC,
                asset="company.example",
                capability_id="external-attack-surface",
                requested_risk=RiskLevel.PASSIVE,
                is_lab="false",  # type: ignore[arg-type]
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "lab context marker must be a bool")


if __name__ == "__main__":
    unittest.main()
