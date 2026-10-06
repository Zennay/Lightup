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
PUBLIC_IP = "198.51.100.10"
PUBLIC_NETWORK = "198.51.100.0/24"
CAPABILITY = "web-baseline"


def _legacy_authorization(*, expired: bool = False) -> Authorization:
    now = datetime.now(timezone.utc)
    return Authorization(
        owner="security-owner@example.test",
        reference="AUTH-DEFENSE-IN-DEPTH",
        valid_from=now - timedelta(minutes=5),
        valid_until=now - timedelta(seconds=1) if expired else now + timedelta(hours=1),
    )


def _durable_grant(*, asset: str = PUBLIC_HOST) -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="grant-defense-in-depth",
        client_id="client-defense-in-depth",
        engagement_id="engagement-defense-in-depth",
        approved_by="security-owner@example.test",
        reference="AUTH-DEFENSE-IN-DEPTH",
        scope=ScopeDefinition(
            assets=(asset,),
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

    def test_explicit_public_network_without_authorization_fails_closed(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        decision = policy.decide(Target(PUBLIC_IP))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_plan_only_blocks_authorized_explicit_public_network(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        target = Target(PUBLIC_IP, authorization=_legacy_authorization())
        decision = policy.decide(target)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

        gate = ActivationGate(
            policy,
            ActivationPolicy(mode=ActivationMode.PLAN_ONLY),
        )
        with self.assertRaisesRegex(PermissionError, "plan-only"):
            gate.issue(target, CAPABILITY)

    def test_public_network_activation_permit_still_needs_durable_grant(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        target = Target(PUBLIC_IP, authorization=_legacy_authorization())
        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="AUTH-NETWORK-DEFENSE-IN-DEPTH",
            ),
        )
        permit = gate.issue(target, CAPABILITY)
        self.assertEqual(permit.target, PUBLIC_IP)
        self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)

        execution = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=permit.target,
                capability_id=permit.capability_id,
                requested_risk=RiskLevel.LOW_IMPACT,
            )
        )
        self.assertFalse(execution.allowed)
        self.assertIn("authorization", execution.reason)

    def test_lab_only_cannot_relabel_authorized_explicit_public_network_as_lab(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        target = Target(PUBLIC_IP, authorization=_legacy_authorization())
        self.assertEqual(policy.decide(target).reason, ScopeReason.EXPLICIT_NETWORK)

        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.LAB_ONLY,
                activation_reference="LAB-NETWORK-DEFENSE-IN-DEPTH",
            ),
        )
        with self.assertRaisesRegex(PermissionError, "public targets"):
            gate.issue(target, CAPABILITY)

    def test_relaxed_scope_auth_switch_cannot_bypass_authorized_activation(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
            require_authorization_for_public=False,
        )
        target = Target(PUBLIC_IP)
        decision = policy.decide(target)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="AUTH-NETWORK-DEFENSE-IN-DEPTH",
            ),
        )
        with self.assertRaisesRegex(PermissionError, "current target authorization"):
            gate.issue(target, CAPABILITY)

    def test_explicit_public_network_all_gates_agree_on_bounded_authorized_path(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        target = Target(PUBLIC_IP, authorization=_legacy_authorization())
        scope_decision = policy.decide(target)
        self.assertTrue(scope_decision.allowed)
        self.assertEqual(scope_decision.reason, ScopeReason.EXPLICIT_NETWORK)

        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="AUTH-NETWORK-DEFENSE-IN-DEPTH",
            ),
        )
        permit = gate.issue(target, CAPABILITY)

        execution = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=permit.target,
                capability_id=permit.capability_id,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=_durable_grant(asset=PUBLIC_IP),
            )
        )
        self.assertTrue(execution.allowed)
        self.assertEqual(execution.reason, "authorized active assessment")

    def test_authorized_target_outside_explicit_public_network_still_fails_scope(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(PUBLIC_NETWORK,),
        )
        decision = policy.decide(
            Target("203.0.113.10", authorization=_legacy_authorization())
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_expired_public_authorization_fails_before_activation(self):
        decision = self.public_scope.decide(
            Target(PUBLIC_HOST, authorization=_legacy_authorization(expired=True))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_not_yet_valid_public_authorization_fails_before_activation(self):
        now = datetime.now(timezone.utc)
        target = Target(
            PUBLIC_HOST,
            authorization=Authorization(
                owner="security-owner@example.test",
                reference="AUTH-FUTURE",
                valid_from=now + timedelta(hours=1),
                valid_until=now + timedelta(hours=2),
            ),
        )
        decision = self.public_scope.decide(target)
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

    def test_activation_permit_does_not_replace_durable_execution_grant(self):
        target = Target(PUBLIC_HOST, authorization=_legacy_authorization())
        gate = ActivationGate(
            self.public_scope,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="AUTH-DEFENSE-IN-DEPTH",
            ),
        )
        permit = gate.issue(target, CAPABILITY)
        self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)

        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=permit.target,
                capability_id=permit.capability_id,
                requested_risk=RiskLevel.LOW_IMPACT,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("authorization", decision.reason)

    def test_durable_execution_grant_does_not_replace_public_scope_authorization(self):
        execution_decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=_durable_grant(),
            )
        )
        self.assertTrue(execution_decision.allowed)

        scope_decision = self.public_scope.decide(Target(PUBLIC_HOST))
        self.assertFalse(scope_decision.allowed)
        self.assertEqual(scope_decision.reason, ScopeReason.AUTHORIZATION_MISSING)

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

    def test_exact_durable_grant_allows_only_the_bounded_standard_path(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.STANDARD,
                authorization=_durable_grant(),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized active assessment")

    def test_expired_durable_grant_is_denied(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="grant-expired",
            client_id="client-defense-in-depth",
            engagement_id="engagement-defense-in-depth",
            approved_by="security-owner@example.test",
            reference="AUTH-EXPIRED",
            scope=ScopeDefinition(
                assets=(PUBLIC_HOST,),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(CAPABILITY,),
            ),
            valid_from=now - timedelta(hours=2),
            valid_until=now - timedelta(hours=1),
        )
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=grant,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("currently valid", decision.reason)

    def test_not_yet_valid_durable_grant_is_denied(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="grant-future",
            client_id="client-defense-in-depth",
            engagement_id="engagement-defense-in-depth",
            approved_by="security-owner@example.test",
            reference="AUTH-FUTURE",
            scope=ScopeDefinition(
                assets=(PUBLIC_HOST,),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(CAPABILITY,),
            ),
            valid_from=now + timedelta(hours=1),
            valid_until=now + timedelta(hours=2),
        )
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=grant,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("currently valid", decision.reason)

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

    def test_explicit_asset_exclusion_overrides_the_grant_allowlist(self):
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="grant-excluded-asset",
            client_id="client-defense-in-depth",
            engagement_id="engagement-defense-in-depth",
            approved_by="security-owner@example.test",
            reference="AUTH-EXCLUDED-ASSET",
            scope=ScopeDefinition(
                assets=(PUBLIC_HOST,),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(CAPABILITY,),
                excluded_assets=(PUBLIC_HOST,),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(hours=1),
        )
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=grant,
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

    def test_lab_active_cannot_borrow_a_durable_grant_without_lab_context(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.LAB_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.LOW_IMPACT,
                authorization=_durable_grant(),
                is_lab=False,
            )
        )
        self.assertFalse(decision.allowed)
        self.assertIn("lab target", decision.reason)

    def test_target_active_lab_flag_cannot_enable_destructive_risk(self):
        decision = self.execution_policy.decide(
            ExecutionRequest(
                interaction=InteractionKind.TARGET_ACTIVE,
                asset=PUBLIC_HOST,
                capability_id=CAPABILITY,
                requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                authorization=_durable_grant(),
                is_lab=True,
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
