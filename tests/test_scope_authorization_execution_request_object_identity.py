import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class _DuckExecutionRequest:
    interaction = InteractionKind.ANALYSIS
    asset = "metadata-only"
    capability_id = "analysis"
    requested_risk = RiskLevel.ANALYSIS_ONLY
    authorization = None
    is_lab = False
    client_id = None
    engagement_id = None


class _DerivedExecutionRequest(ExecutionRequest):
    pass


class ExecutionRequestObjectIdentityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def test_exact_execution_request_control_is_allowed(self):
        request = ExecutionRequest(
            interaction=InteractionKind.ANALYSIS,
            asset="metadata-only",
            capability_id="analysis",
            requested_risk=RiskLevel.ANALYSIS_ONLY,
            is_lab=False,
        )

        decision = self.policy.decide(request)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "analysis-only")

    def test_duck_typed_request_fails_closed_before_policy_evaluation(self):
        decision = self.policy.decide(_DuckExecutionRequest())  # type: ignore[arg-type]

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "request must be an exact ExecutionRequest")

    def test_execution_request_subclass_fails_closed_before_policy_evaluation(self):
        request = _DerivedExecutionRequest(
            interaction=InteractionKind.ANALYSIS,
            asset="metadata-only",
            capability_id="analysis",
            requested_risk=RiskLevel.ANALYSIS_ONLY,
            is_lab=False,
        )

        decision = self.policy.decide(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "request must be an exact ExecutionRequest")


if __name__ == "__main__":
    unittest.main()
