"""RED contract: unknown interaction kinds must never inherit target-active authority.

This module is intentionally isolated from production ownership of execution_policy.py.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class UnknownInteractionKindContract(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-unknown-kind",
            client_id="client-fixture",
            engagement_id="eng-fixture",
            approved_by="owner@example.test",
            reference="signed-fixture",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                allowed_capabilities=("web-baseline",),
                max_risk=RiskLevel.STANDARD,
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=5),
        )

    def test_unknown_string_kind_cannot_borrow_valid_active_grant(self):
        decision = ExecutionPolicy().decide(ExecutionRequest(
            interaction="future_active_kind",
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
        ))
        self.assertFalse(decision.allowed)

    def test_unknown_object_kind_cannot_borrow_valid_active_grant(self):
        decision = ExecutionPolicy().decide(ExecutionRequest(
            interaction=object(),
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
        ))
        self.assertFalse(decision.allowed)

    def test_canonical_target_active_still_allowed(self):
        decision = ExecutionPolicy().decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
        ))
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
