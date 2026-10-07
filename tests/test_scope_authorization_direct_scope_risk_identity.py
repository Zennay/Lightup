import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from enum import IntEnum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class _ForeignRisk(IntEnum):
    ELEVATED = 4
    UNBOUNDED = 99


class DirectScopeRiskIdentityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        self.now = datetime.now(timezone.utc)

    def _decision(self, max_risk):
        scope = ScopeDefinition(
            assets=("app.example",),
            max_risk=max_risk,
            allowed_capabilities=("web-baseline",),
        )
        grant = AuthorizationGrant(
            grant_id="grant-risk",
            client_id="client-a",
            engagement_id="eng-a",
            approved_by="operator-a",
            reference="AUTH-RISK",
            scope=scope,
            valid_from=self.now - timedelta(days=1),
            valid_until=self.now + timedelta(days=1),
        )
        request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="app.example",
            capability_id="web-baseline",
            requested_risk=RiskLevel.ELEVATED,
            authorization=grant,
            client_id="client-a",
            engagement_id="eng-a",
        )
        return self.policy.decide(request)

    def test_canonical_elevated_scope_allows_elevated_request(self):
        decision = self._decision(RiskLevel.ELEVATED)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized active assessment")

    def test_canonical_standard_scope_still_denies_elevated_request(self):
        decision = self._decision(RiskLevel.STANDARD)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "requested risk exceeds authorized maximum")

    def test_raw_high_integer_scope_risk_fails_closed(self):
        decision = self._decision(99)  # type: ignore[arg-type]

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "authorization scope risk must be a RiskLevel")

    def test_raw_matching_integer_scope_risk_is_still_noncanonical(self):
        decision = self._decision(4)  # type: ignore[arg-type]

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "authorization scope risk must be a RiskLevel")

    def test_foreign_integer_enum_scope_risk_cannot_widen_authority(self):
        decision = self._decision(_ForeignRisk.UNBOUNDED)  # type: ignore[arg-type]

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "authorization scope risk must be a RiskLevel")

    def test_boolean_scope_risk_is_rejected_before_numeric_comparison(self):
        decision = self._decision(True)  # type: ignore[arg-type]

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "authorization scope risk must be a RiskLevel")


if __name__ == "__main__":
    unittest.main()
