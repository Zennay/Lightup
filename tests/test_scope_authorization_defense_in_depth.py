import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


PUBLIC_HOST = "public.example.test"
CAPABILITY = "web-baseline"


def _legacy_authorization(*, expired: bool = False) -> Authorization:
    now = datetime.now(timezone.utc)
    return Authorization(
        owner="security-owner@example.test",
        reference="AUTH-DEFENSE-IN-DEPTH",
        valid_from=now - timedelta(minutes=5),
        valid_until=now - timedelta(seconds=1) if expired else now + timedelta(hours=1),
    )


def _durable_grant() -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="grant-defense-in-depth",
        client_id="client-defense-in-depth",
        engagement_id="engagement-defense-in-depth",
        approved_by="security-owner@example.test",
        reference="AUTH-DEFENSE-IN-DEPTH",
        scope=ScopeDefinition(
            assets=(PUBLIC_HOST,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(CAPABILITY,),
        ),
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
    )


class ScopeAuthorizationDefenseInDepthTests(unittest.TestCase):
    def setUp(self):
        self.public_scope = ScopePolicy(explicit_hosts=frozenset({PUBLIC_HOST}))
        self.execution_policy = ExecutionPolicy()

    def test_unknown_public_target_fails_at_scope_boundary(self):
        decision = ScopePolicy().decide(Target(PUBLIC_HOST))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_public_target_without_authorization_fails_at_scope_boundary(self):
        decision = self.public_scope.decide(Target(PUBLIC_HOST))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_expired_public_authorization_fails_before_activation(self):
        decision = self.public_scope.decide(
            Target(PUBLIC_HOST, authorization=_legacy_authorization(expired=True))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_plan_only_still_blocks_an_in_scope_public_target(self):
        target = Target(PUBLIC_HOST, authorization=_legacy_authorization())
        self.assertTrue(self.public_scope.decide(target).allowed)

        gate = ActivationGate(
            self.public_scope,
            ActivationPolicy(mode=ActivationMode.PLAN_ONLY),
        )
        with self.assertRaisesRegex(PermissionError, "plan-only"):
            gate.issue(target, CAPABILITY)

    def test_lab_only_cannot_relabel_an_authorized_public_target_as_lab(self):
        target = Target(PUBLIC_HOST, authorization=_legacy_authorization())
        self.assertTrue(self.public_scope.decide(target).allowed)

        gate = ActivationGate(
            self.public_scope,
            ActivationPolicy(
                mode=ActivationMode.LAB_ONLY,
                activation_reference="LAB-DEFENSE-IN-DEPTH",
            ),
        )
        with self.assertRaisesRegex(PermissionError, "public targets"):
            gate.issue(target, CAPABILITY)

    def test_target_active_without_durable_grant_fails_at_execution_policy(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("authorization", decision.reason)

    def test_durable_grant_cannot_authorize_a_different_asset(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset="other.example.test",
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=_durable_grant(),
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("asset", decision.reason)

    def test_durable_grant_cannot_authorize_a_different_capability(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id="network-services",
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=_durable_grant(),
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("capability", decision.reason)

    def test_durable_grant_cannot_authorize_risk_above_its_ceiling(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.ELEVATED,
                authorization=_durable_grant(),
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("risk", decision.reason)

    def test_destructive_target_active_risk_is_denied_even_with_grant(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                authorization=_durable_grant(),
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("isolated labs", decision.reason)

    def test_passive_public_cannot_request_active_risk(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.PASSIVE_PUBLIC,
                asset=PUBLIC_HOST,
                capability_id="external-attack-surface",
                requested_risk=RiskLevel.STANDARD,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("passive discovery", decision.reason)

    def test_analysis_cannot_request_passive_or_active_risk(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.ANALYSIS,
                asset=PUBLIC_HOST,
                capability_id="reporting",
                requested_risk=RiskLevel.PASSIVE,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("analysis mode", decision.reason)


if __name__ == "__main__":
    unittest.main()
