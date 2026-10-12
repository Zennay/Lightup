"""#773 — direct ScopeDefinition.max_risk identity, isolated expected-RED contract.

Pinned to PR #100 exact head ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f.
Tests invoke only the in-memory ExecutionPolicy with synthetic .test assets.
No ToolExecutor, handler, network, target interaction, grants persisted or scans.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import IntEnum

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class ForeignRisk(IntEnum):
    SAME_STANDARD = 3
    OVERSIZED = 99


def _case(
    max_risk,
    requested=RiskLevel.STANDARD,
    asset="owned.example.test",
    capability="web-baseline",
    client_id="client-synthetic",
    engagement_id="engagement-synthetic",
):
    now = datetime.now(timezone.utc)
    scope = ScopeDefinition(
        assets=("owned.example.test",),
        allowed_capabilities=("web-baseline",),
        max_risk=max_risk,
    )
    grant = AuthorizationGrant(
        grant_id="synthetic-g",
        client_id="client-synthetic",
        engagement_id="engagement-synthetic",
        approved_by="synthetic-operator",
        reference="synthetic-scope-only",
        scope=scope,
        valid_from=now - timedelta(minutes=10),
        valid_until=now + timedelta(minutes=10),
    )
    request = ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=asset,
        capability_id=capability,
        requested_risk=requested,
        authorization=grant,
        client_id=client_id,
        engagement_id=engagement_id,
    )
    return request


class DirectScopeRiskExpectedRed(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutionPolicy()

    def _must_refuse(self, maximum, requested):
        request = _case(maximum, requested)
        original_scope = request.authorization.scope
        original_maximum = original_scope.max_risk
        result = self.policy.decide(request)
        self.assertFalse(result.allowed, "noncanonical scope max_risk enlarged authority")
        self.assertIs(request.authorization.scope, original_scope)
        self.assertIs(request.authorization.scope.max_risk, original_maximum)

    @unittest.expectedFailure
    def test_raw_high_integer_cannot_expand_scope(self):
        self._must_refuse(99, RiskLevel.STANDARD)

    @unittest.expectedFailure
    def test_boolean_true_is_not_an_authorized_risk(self):
        self._must_refuse(True, RiskLevel.ANALYSIS_ONLY)

    @unittest.expectedFailure
    def test_boolean_false_is_not_an_authorized_risk(self):
        self._must_refuse(False, RiskLevel.ANALYSIS_ONLY)

    @unittest.expectedFailure
    def test_foreign_intenum_over_ceiling_cannot_expand_scope(self):
        self._must_refuse(ForeignRisk.OVERSIZED, RiskLevel.STANDARD)

    @unittest.expectedFailure
    def test_foreign_intenum_same_numeric_value_is_not_risklevel(self):
        self._must_refuse(ForeignRisk.SAME_STANDARD, RiskLevel.STANDARD)

    @unittest.expectedFailure
    def test_floating_point_over_ceiling_cannot_expand_scope(self):
        self._must_refuse(99.0, RiskLevel.STANDARD)

    @unittest.expectedFailure
    def test_decimal_numeric_lookalike_cannot_expand_scope(self):
        self._must_refuse(Decimal(99), RiskLevel.STANDARD)

    @unittest.expectedFailure
    def test_string_risk_must_return_denial_not_raise_typeerror(self):
        # Current numeric comparison raises TypeError: no canonical decision.
        self._must_refuse("3", RiskLevel.STANDARD)

    def test_canonical_standard_scope_allows_matching_standard_request(self):
        request = _case(RiskLevel.STANDARD, RiskLevel.STANDARD)
        decision = self.policy.decide(request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized active assessment")

    def test_canonical_low_ceiling_denies_higher_requested_risk(self):
        request = _case(RiskLevel.PASSIVE, RiskLevel.LOW_IMPACT)
        self.assertFalse(self.policy.decide(request).allowed)

    def test_canonical_scope_still_requires_exact_host_membership(self):
        request = _case(
            RiskLevel.STANDARD,
            RiskLevel.LOW_IMPACT,
            asset="unowned.example.test",
        )
        self.assertFalse(self.policy.decide(request).allowed)

    def test_canonical_scope_still_requires_capability_membership(self):
        request = _case(
            RiskLevel.STANDARD,
            RiskLevel.LOW_IMPACT,
            capability="identity-access",
        )
        self.assertFalse(self.policy.decide(request).allowed)

    def test_client_identity_gate_precedes_risk_comparison(self):
        request = _case(
            99,
            RiskLevel.STANDARD,
            client_id="another-synthetic-tenant",
        )
        decision = self.policy.decide(request)
        self.assertFalse(decision.allowed)
        self.assertIn("client", decision.reason)

    def test_revoked_authorization_denies_even_under_high_invalid_ceiling(self):
        request = _case(99, RiskLevel.STANDARD)
        revoked_grant = replace(
            request.authorization,
            revoked_at=datetime.now(timezone.utc),
            revoked_by="synthetic-reviewer",
            revocation_reason="offline-canary",
        )
        decision = self.policy.decide(replace(request, authorization=revoked_grant))
        self.assertFalse(decision.allowed)

    def test_invalid_scope_does_not_mutate_request_or_grant(self):
        request = _case(99, RiskLevel.LOW_IMPACT)
        original = (
            request.asset,
            request.capability_id,
            request.requested_risk,
            request.authorization.scope,
        )
        self.policy.decide(request)
        after = (
            request.asset,
            request.capability_id,
            request.requested_risk,
            request.authorization.scope,
        )
        self.assertEqual(after, original)


if __name__ == "__main__":
    unittest.main()
