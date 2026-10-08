"""Offline acceptance: unknown interaction kinds must never inherit TARGET_ACTIVE authority."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class InteractionKindFailClosedAcceptance(unittest.TestCase):
    def test_unrecognized_interaction_never_inherits_authorized_target_path(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="grant-interaction-kind",
            client_id="client-kind",
            engagement_id="eng-kind",
            approved_by="owner@example.test",
            reference="signed-scope-kind",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=5),
        )
        policy = ExecutionPolicy()
        canonical = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="app.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=grant,
        )
        self.assertTrue(policy.decide(canonical).allowed)
        for unrecognized in ("target_active", "future_active", None, 0, object()):
            with self.subTest(value=repr(unrecognized)):
                malformed = ExecutionRequest(
                    interaction=unrecognized,
                    asset=canonical.asset,
                    capability_id=canonical.capability_id,
                    requested_risk=canonical.requested_risk,
                    authorization=grant,
                )
                decision = policy.decide(malformed)
                self.assertFalse(decision.allowed, "unknown interaction inherited active authority")


if __name__ == "__main__":
    unittest.main()
