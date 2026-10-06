import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="grant-1",
            client_id="client-1",
            engagement_id="eng-1",
            approved_by="security-owner@example.test",
            reference="signed-roE-1",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        self.policy = ExecutionPolicy()

    def test_public_passive_discovery_does_not_require_authorization(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.PASSIVE_PUBLIC,
                asset="company.example",
                capability_id="external-attack-surface",
                requested_risk=RiskLevel.PASSIVE,
            )
        )
        self.assertTrue(decision.allowed)

    def test_unauthorized_active_target_is_denied(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.LOW_IMPACT,
            )
        )
        self.assertFalse(decision.allowed)

    def test_authorized_target_within_scope_is_allowed(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.STANDARD,
                authorization=self.grant,
            )
        )
        self.assertTrue(decision.allowed)

    def test_empty_capability_scope_denies_active_capability(self):
        empty_scope = replace(
            self.grant,
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(),
            ),
        )
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=empty_scope,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "capability is outside the authorized scope")

    def test_revoked_authorization_is_denied(self):
        revoked = replace(
            self.grant,
            revoked_at=datetime.now(timezone.utc),
            revoked_by="op-2",
            revocation_reason="scope withdrawn",
        )
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.STANDARD,
                authorization=revoked,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "authorization is not currently valid")

    def test_risk_escalation_is_denied(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.ELEVATED,
                authorization=self.grant,
            )
        )
        self.assertFalse(decision.allowed)

    def test_destructive_risk_is_lab_only(self):
        decision = self.policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="app.example.test",
                capability_id="web-baseline",
                requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                authorization=self.grant,
            )
        )
        self.assertFalse(decision.allowed)

    def test_unauthorized_discovery_rejects_interactive_signal(self):
        profile = ProspectProfile("p-1", "Example")
        signal = ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="requires verification",
            source="collector",
            confidence=0.7,
            public_source=True,
            requires_target_interaction=True,
        )
        with self.assertRaises(PermissionError):
            profile.add_signal(signal)


if __name__ == "__main__":
    unittest.main()
