"""Offline replay contract for scope authorization decisions.

Tests deliberately use inert strings: no targets, transport or capability handlers.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ScopeAuthorizationReplayContract(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="replay-grant",
            client_id="offline-client",
            engagement_id="offline-engagement",
            approved_by="offline-reviewer",
            reference="offline-consent",
            scope=ScopeDefinition(
                assets=("alpha.example.test", "beta.example.test"),
                excluded_assets=("beta.example.test",),
                allowed_capabilities=("inert-check",),
                max_risk=RiskLevel.LOW_IMPACT,
            ),
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )
        self.policy = ExecutionPolicy()

    def request(self, *, asset="alpha.example.test", capability="inert-check",
                risk=RiskLevel.LOW_IMPACT, grant=None):
        return ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset=asset,
            capability_id=capability,
            requested_risk=risk,
            authorization=self.grant if grant is None else grant,
        )

    def test_replayed_decisions_preserve_inputs_and_reason(self):
        request = self.request()
        snapshot = repr((request, self.grant, self.grant.scope))
        decisions = [self.policy.decide(request) for _ in range(8)]
        self.assertTrue(all(decision == decisions[0] for decision in decisions))
        self.assertTrue(decisions[0].allowed)
        self.assertEqual(repr((request, self.grant, self.grant.scope)), snapshot)

    def test_excluded_member_never_becomes_allowed_after_successful_decision(self):
        permitted = self.request()
        excluded = self.request(asset="beta.example.test")
        self.assertTrue(self.policy.decide(permitted).allowed)
        for _ in range(4):
            decision = self.policy.decide(excluded)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "asset is outside the authorized scope")
            self.assertTrue(self.policy.decide(permitted).allowed)

    def test_capability_and_risk_denials_remain_stable_after_allowed_decision(self):
        allowed = self.request()
        cases = (
            (self.request(capability="unlisted-check"), "capability is outside the authorized scope"),
            (self.request(risk=RiskLevel.STANDARD), "requested risk exceeds authorized maximum"),
        )
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                self.assertTrue(self.policy.decide(allowed).allowed)
                self.assertEqual(self.policy.decide(candidate).reason, expected)
                self.assertFalse(self.policy.decide(candidate).allowed)
                self.assertTrue(self.policy.decide(allowed).allowed)

    def test_explicitly_missing_authorization_still_denied_after_granted_request(self):
        self.assertTrue(self.policy.decide(self.request()).allowed)
        no_grant = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="alpha.example.test",
            capability_id="inert-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=None,
        )
        for _ in range(3):
            decision = self.policy.decide(no_grant)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "active target interaction requires authorization")


    def test_expired_grant_remains_denied_after_valid_grant_decision(self):
        from dataclasses import replace

        now = datetime.now(timezone.utc)
        expired = replace(
            self.grant,
            valid_from=now - timedelta(days=3),
            valid_until=now - timedelta(days=1),
        )
        self.assertTrue(self.policy.decide(self.request()).allowed)
        for _ in range(4):
            denied = self.policy.decide(self.request(grant=expired))
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.reason, "authorization is not currently valid")
            self.assertTrue(self.policy.decide(self.request()).allowed)

    def test_future_grant_remains_denied_after_valid_grant_decision(self):
        from dataclasses import replace

        now = datetime.now(timezone.utc)
        future = replace(
            self.grant,
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=3),
        )
        self.assertTrue(self.policy.decide(self.request()).allowed)
        for _ in range(4):
            denied = self.policy.decide(self.request(grant=future))
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.reason, "authorization is not currently valid")
            self.assertTrue(self.policy.decide(self.request()).allowed)

if __name__ == "__main__":
    unittest.main()
