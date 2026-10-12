"""#740 exact nested grant scope identity — independent expected-RED tests.

Pinned to immutable #100 owner head ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f.
Pure ExecutionPolicy.decide in memory; no dispatcher, handler or target I/O.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


ASSET = "owned.example.test"
FOREIGN = "outside.example.test"
CAPABILITY = "web-baseline"
OTHER_CAPABILITY = "identity-access"


class AssetMintingScope(ScopeDefinition):
    def allows_asset(self, asset):
        return True


class CapabilityMintingScope(ScopeDefinition):
    def allows_capability(self, capability_id):
        return True


class InnocentScopeSubtype(ScopeDefinition):
    pass


class DuckScope:
    max_risk = RiskLevel.STANDARD
    def allows_asset(self, asset):
        return True
    def allows_capability(self, capability_id):
        return True


class CallingScope:
    def __init__(self):
        self.calls = []
    @property
    def max_risk(self):
        self.calls.append("max_risk")
        return RiskLevel.STANDARD
    def allows_asset(self, asset):
        self.calls.append("allows_asset")
        return True
    def allows_capability(self, capability_id):
        self.calls.append("allows_capability")
        return True


def _scope(scope_type=ScopeDefinition):
    return scope_type(
        assets=(ASSET,),
        max_risk=RiskLevel.STANDARD,
        allowed_capabilities=(CAPABILITY,),
    )


def _request(scope, asset=ASSET, capability=CAPABILITY, risk=RiskLevel.LOW_IMPACT):
    now = datetime.now(timezone.utc)
    grant = AuthorizationGrant(
        grant_id="g-offline",
        client_id="client-offline",
        engagement_id="engagement-offline",
        approved_by="synthetic-owner",
        reference="offline-only",
        scope=scope,
        valid_from=now - timedelta(minutes=2),
        valid_until=now + timedelta(minutes=30),
    )
    return ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=asset,
        capability_id=capability,
        requested_risk=risk,
        authorization=grant,
        client_id=grant.client_id,
        engagement_id=grant.engagement_id,
    )


class NestedScopeExactIdentityExpectedRed(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def test_exact_scope_matching_asset_and_capability_allowed(self):
        decision = self.policy.decide(_request(_scope()))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized active assessment")

    def test_exact_scope_rejects_foreign_asset(self):
        self.assertFalse(self.policy.decide(_request(_scope(), asset=FOREIGN)).allowed)

    def test_exact_scope_rejects_foreign_capability(self):
        self.assertFalse(
            self.policy.decide(
                _request(_scope(), capability=OTHER_CAPABILITY)
            ).allowed
        )

    def test_exact_scope_rejects_risk_beyond_grant_ceiling(self):
        self.assertFalse(
            self.policy.decide(_request(_scope(), risk=RiskLevel.ELEVATED)).allowed
        )

    def test_missing_grant_still_denies_target_active(self):
        request = _request(_scope())
        from dataclasses import replace
        self.assertFalse(
            self.policy.decide(replace(request, authorization=None)).allowed
        )

    @unittest.expectedFailure
    def test_subclass_that_mints_asset_cannot_grant_foreign_asset(self):
        request = _request(_scope(AssetMintingScope), asset=FOREIGN)
        self.assertFalse(self.policy.decide(request).allowed)

    @unittest.expectedFailure
    def test_subclass_that_mints_capability_cannot_grant_foreign_capability(self):
        request = _request(_scope(CapabilityMintingScope), capability=OTHER_CAPABILITY)
        self.assertFalse(self.policy.decide(request).allowed)

    @unittest.expectedFailure
    def test_pure_subclass_identity_must_fail_even_if_behavior_matches(self):
        request = _request(_scope(InnocentScopeSubtype))
        self.assertFalse(self.policy.decide(request).allowed)

    @unittest.expectedFailure
    def test_duck_scope_cannot_mint_both_asset_and_capability(self):
        request = _request(DuckScope(), asset=FOREIGN, capability=OTHER_CAPABILITY)
        self.assertFalse(self.policy.decide(request).allowed)

    @unittest.expectedFailure
    def test_grant_scope_without_maxrisk_must_return_denial_not_attributeerror(self):
        request = _request(object())
        self.assertFalse(self.policy.decide(request).allowed)

    @unittest.expectedFailure
    def test_foreign_scope_attributes_are_never_called_as_authority(self):
        scope = CallingScope()
        request = _request(scope, asset=FOREIGN, capability=OTHER_CAPABILITY)
        result = self.policy.decide(request)
        self.assertFalse(result.allowed)
        self.assertEqual(scope.calls, [], "untrusted scope methods were evaluated")

    def test_exact_canonical_scope_is_not_mutated_by_policy_decision(self):
        scope = _scope()
        request = _request(scope, asset=FOREIGN)
        identity = (request.asset, scope.assets, scope.max_risk,
                    scope.allowed_capabilities, request.authorization)
        self.assertFalse(self.policy.decide(request).allowed)
        after = (request.asset, scope.assets, scope.max_risk,
                 scope.allowed_capabilities, request.authorization)
        self.assertEqual(identity, after)

    def test_expired_exact_grant_remains_denied(self):
        from dataclasses import replace
        request = _request(_scope())
        expired = replace(
            request.authorization,
            valid_from=datetime.now(timezone.utc) - timedelta(days=2),
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        self.assertFalse(
            self.policy.decide(replace(request, authorization=expired)).allowed
        )


if __name__ == "__main__":
    unittest.main()
