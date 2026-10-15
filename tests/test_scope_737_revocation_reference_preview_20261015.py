"""#737 strictly test-only reference for stale grant revocation provenance.

Temporary unittest.mock patch scoped to each test only: NEVER installed source,
never global activation, never a customer grant or production authorization.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


FIXTURE_NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
FIXTURE_ASSET = "fictional-revocation-matrix.example.test"
FIXTURE_CAP = "fictional-readonly-capability"
ORIGINAL_CURRENT = AuthorizationGrant.is_current


def reference_current(self, now=None):
    """Narrow-only proposed condition; original source called for clean metadata."""
    if self.revoked_at is None and (
        self.revoked_by is not None or self.revocation_reason is not None
    ):
        return False
    return ORIGINAL_CURRENT(self, now)


def grant(**kwargs):
    value = AuthorizationGrant(
        grant_id="fixture-revocation-coherence",
        client_id="fictional-client",
        engagement_id="fictional-engagement",
        approved_by="fictional-operator",
        reference="fixture-review-only",
        scope=ScopeDefinition(
            assets=(FIXTURE_ASSET,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(FIXTURE_CAP,),
        ),
        valid_from=FIXTURE_NOW - timedelta(days=1),
        valid_until=FIXTURE_NOW + timedelta(days=1),
    )
    return replace(value, **kwargs)


def active_decision(g):
    return ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset=FIXTURE_ASSET,
            capability_id=FIXTURE_CAP,
            requested_risk=RiskLevel.STANDARD,
            authorization=g,
            client_id="fictional-client",
            engagement_id="fictional-engagement",
        )
    )


class TestOnlyRevocationReferenceAcceptance(unittest.TestCase):
    def tearDown(self):
        # Strong cross-test tripwire: reference must not leak outside patch.
        self.assertIs(AuthorizationGrant.is_current, ORIGINAL_CURRENT)

    def test_reference_is_not_installed_as_source_by_default(self):
        self.assertIs(AuthorizationGrant.is_current, ORIGINAL_CURRENT)

    def test_installed_source_witness_is_precise_and_in_memory(self):
        # This ordinary witness establishes the *actual* pre-fix defect.
        # Source owner must retire it when the genuine installed fix lands.
        self.assertTrue(grant(revoked_by="fictional-operator").is_current(FIXTURE_NOW))
        self.assertTrue(active_decision(grant(revocation_reason="withdrawn")).allowed)

    def test_reference_blocks_stale_actor_in_real_installed_policy_chain(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(active_decision(grant(revoked_by="fictional-operator")).allowed)

    def test_reference_blocks_stale_reason_in_real_installed_policy_chain(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(active_decision(grant(revocation_reason="withdrawn")).allowed)

    def test_reference_blocks_actor_and_reason_in_real_policy_chain(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(
                active_decision(
                    grant(revoked_by="fictional-operator", revocation_reason="withdrawn")
                ).allowed
            )

    def test_reference_denies_even_empty_but_present_actor(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(grant(revoked_by="").is_current(FIXTURE_NOW))

    def test_reference_denies_even_empty_but_present_reason(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(grant(revocation_reason="").is_current(FIXTURE_NOW))

    def test_reference_preserves_normal_unrevoked_grant(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertTrue(grant().is_current(FIXTURE_NOW))
            self.assertTrue(active_decision(grant()).allowed)

    def test_reference_preserves_explicit_revocation_denial(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            g = grant(
                revoked_at=FIXTURE_NOW - timedelta(minutes=1),
                revoked_by="fictional-operator",
                revocation_reason="withdrawn",
            )
            self.assertFalse(g.is_current(FIXTURE_NOW))
            self.assertFalse(active_decision(g).allowed)

    def test_reference_preserves_canonical_future_and_expired_denial(self):
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(
                grant(valid_from=FIXTURE_NOW + timedelta(seconds=1)).is_current(FIXTURE_NOW)
            )
            self.assertFalse(
                grant(valid_until=FIXTURE_NOW - timedelta(seconds=1)).is_current(FIXTURE_NOW)
            )

    def test_reference_does_not_mutate_frozen_grant(self):
        g = grant(revoked_by="fictional-operator", revocation_reason="withdrawn")
        before = (g.revoked_at, g.revoked_by, g.revocation_reason, g.scope)
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertFalse(g.is_current(FIXTURE_NOW))
        self.assertEqual((g.revoked_at, g.revoked_by, g.revocation_reason, g.scope), before)

    def test_reference_cannot_escape_into_normal_global_method(self):
        original_id = id(AuthorizationGrant.is_current)
        with patch.object(AuthorizationGrant, "is_current", new=reference_current):
            self.assertIs(AuthorizationGrant.is_current, reference_current)
            self.assertFalse(grant(revoked_by="fictional-operator").is_current(FIXTURE_NOW))
        self.assertEqual(id(AuthorizationGrant.is_current), original_id)


if __name__ == "__main__":
    unittest.main()
