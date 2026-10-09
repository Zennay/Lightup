"""Offline regression: a lab context flag is not an active-target authorization grant.

No sockets, DNS, approvals, filesystem targets or production dispatch are used.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class LabMarkerNonBypassTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="synthetic-grant",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="owner@example.test",
            reference="synthetic-only",
            scope=ScopeDefinition(
                assets=("authorized.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("synthetic-check",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=5),
        )

    def test_lab_flag_without_grant_cannot_authorize_target_active(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("authorization", result.reason)

    def test_lab_flag_with_grant_does_not_override_asset_scope(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="outside.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("scope", result.reason)

    def test_lab_flag_with_grant_does_not_override_capability_scope(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="not-granted",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("scope", result.reason)

    def test_lab_flag_does_not_override_risk_ceiling(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.ELEVATED,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("risk", result.reason)

    def test_lab_flag_does_not_enable_destructive_target_risk(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=self.grant,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("destructive", result.reason)

    def test_lab_flag_does_not_override_expired_grant(self):
        expired = AuthorizationGrant(
            grant_id="expired-synthetic-grant",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="owner@example.test",
            reference="synthetic-only",
            scope=self.grant.scope,
            valid_from=datetime.now(timezone.utc) - timedelta(hours=2),
            valid_until=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=expired,
            is_lab=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("valid", result.reason)

    def test_valid_target_grant_remains_allowed_with_or_without_lab_marker(self):
        decisions = [
            self.policy.decide(ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="authorized.example.test",
                capability_id="synthetic-check",
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=self.grant,
                is_lab=marker,
            ))
            for marker in (False, True)
        ]
        self.assertTrue(all(decision.allowed for decision in decisions))
        self.assertEqual(decisions[0], decisions[1])

    def test_denied_target_outside_scope_is_independent_of_lab_marker(self):
        decisions = [
            self.policy.decide(ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="outside.example.test",
                capability_id="synthetic-check",
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=self.grant,
                is_lab=marker,
            ))
            for marker in (False, True)
        ]
        self.assertFalse(any(decision.allowed for decision in decisions))
        self.assertEqual(decisions[0], decisions[1])

    def test_future_grant_cannot_be_activated_by_lab_marker(self):
        now = datetime.now(timezone.utc)
        future = AuthorizationGrant(
            grant_id="future-synthetic-grant",
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="owner@example.test",
            reference="synthetic-only",
            scope=self.grant.scope,
            valid_from=now + timedelta(hours=1),
            valid_until=now + timedelta(hours=2),
        )
        for marker in (False, True):
            with self.subTest(is_lab=marker):
                decision = self.policy.decide(ExecutionRequest(
                    interaction=InteractionKind.TARGET_ACTIVE,
                    asset="authorized.example.test",
                    capability_id="synthetic-check",
                    requested_risk=RiskLevel.LOW_IMPACT,
                    authorization=future,
                    is_lab=marker,
                ))
                self.assertFalse(decision.allowed)
                self.assertIn("valid", decision.reason)

    def test_lab_interaction_without_lab_flag_denied_despite_grant(self):
        result = self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="authorized.example.test",
            capability_id="synthetic-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=self.grant,
            is_lab=False,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("lab", result.reason)


if __name__ == "__main__":
    unittest.main()
