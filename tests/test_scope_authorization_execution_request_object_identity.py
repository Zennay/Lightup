import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


_REQUEST_FIELDS = {
    "interaction",
    "asset",
    "capability_id",
    "requested_risk",
    "authorization",
    "is_lab",
    "client_id",
    "engagement_id",
}


class _DuckExecutionRequest:
    def __init__(self):
        self.access_log = []

    def __getattribute__(self, name):
        if name in _REQUEST_FIELDS:
            object.__getattribute__(self, "access_log").append(name)
        return object.__getattribute__(self, name)

    interaction = InteractionKind.ANALYSIS
    asset = "metadata-only"
    capability_id = "analysis"
    requested_risk = RiskLevel.ANALYSIS_ONLY
    authorization = None
    is_lab = False
    client_id = None
    engagement_id = None


class _DerivedExecutionRequest(ExecutionRequest):
    access_log = []

    def __getattribute__(self, name):
        if name in _REQUEST_FIELDS:
            type(self).access_log.append(name)
        return super().__getattribute__(name)


class ExecutionRequestObjectIdentityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        _DerivedExecutionRequest.access_log.clear()

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

    def test_duck_typed_request_fails_before_any_request_field_access(self):
        request = _DuckExecutionRequest()

        decision = self.policy.decide(request)  # type: ignore[arg-type]

        self.assertEqual(request.access_log, [])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "request must be an exact ExecutionRequest")

    def test_execution_request_subclass_fails_before_any_request_field_access(self):
        request = _DerivedExecutionRequest(
            interaction=InteractionKind.ANALYSIS,
            asset="metadata-only",
            capability_id="analysis",
            requested_risk=RiskLevel.ANALYSIS_ONLY,
            is_lab=False,
        )

        decision = self.policy.decide(request)

        self.assertEqual(_DerivedExecutionRequest.access_log, [])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "request must be an exact ExecutionRequest")


if __name__ == "__main__":
    unittest.main()
