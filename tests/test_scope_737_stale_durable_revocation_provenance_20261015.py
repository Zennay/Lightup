"""#737 source-owner acceptance: stale revocation metadata must not remain current.

All fixtures are synthetic and in-memory. This file invokes actual installed
AuthorizationGrant.is_current and ExecutionPolicy.decide, never a handler.
Intentional expectedFailure means an ORIGINAL SOURCE DEFECT is still open.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import (
    ExecutionPolicy,
    ExecutionRequest,
    InteractionKind,
)


NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
# Stable fixtures: direct ExecutionPolicy uses the ACTUAL current UTC clock.
# A ±1-day window around NOW would expire after 2026-10-16 and turn original
# source RED tests into misleading successes or break positive controls.
WINDOW_START = datetime(2000, 1, 1, tzinfo=timezone.utc)
WINDOW_END = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
LATER = datetime(2050, 1, 1, tzinfo=timezone.utc)
ASSET = "fixture-revocation.example.test"
CAPABILITY = "fixture-read-only-baseline"


def grant(**overrides: object) -> AuthorizationGrant:
    base = AuthorizationGrant(
        grant_id="fictional-grant-737",
        client_id="fictional-client-737",
        engagement_id="fictional-engagement-737",
        approved_by="fictional-operator",
        reference="fixture-only-review",
        scope=ScopeDefinition(
            assets=(ASSET,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(CAPABILITY,),
        ),
        valid_from=WINDOW_START,
        valid_until=WINDOW_END,
    )
    return replace(base, **overrides)


def decision(current_grant: AuthorizationGrant, **request_overrides: object):
    request = ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset=ASSET,
        capability_id=CAPABILITY,
        requested_risk=RiskLevel.STANDARD,
        authorization=current_grant,
        client_id=current_grant.client_id,
        engagement_id=current_grant.engagement_id,
    )
    return ExecutionPolicy().decide(replace(request, **request_overrides))


def decision_at_clock(current_grant: AuthorizationGrant, time: datetime):
    """Use the real installed policy under an exact synthetic future clock.

    Only the engagements module's imported wall clock is scoped-patched, NOT
    AuthorizationGrant.is_current or ExecutionPolicy.decide themselves.
    """
    with patch("lightup.engagements.datetime") as clock:
        clock.now.return_value = time
        return decision(current_grant)


class DurableRevocationProvenanceSourceAcceptance(unittest.TestCase):
    def test_canonical_never_revoked_is_current_at_bounded_instant(self):
        valid = grant()
        self.assertTrue(valid.is_current(NOW))
        self.assertFalse(valid.is_revoked)

    def test_canonical_never_revoked_preserves_target_policy_allow(self):
        self.assertTrue(decision(grant()).allowed)

    def test_clean_grant_still_current_long_after_original_fixture_date(self):
        # Expiry must never accidentally turn an unsafe-source RED green.
        self.assertTrue(grant().is_current(LATER))

    def test_original_stale_provenance_canary_is_still_unsafe_in_2050(self):
        # Explicit diagnostic; owner must retire/invert after the source fix.
        stale = grant(revoked_by="fictional-revoker")
        self.assertTrue(stale.is_current(NOW))
        self.assertTrue(stale.is_current(LATER))

    def test_real_policy_remains_valid_when_clock_moves_to_2050(self):
        self.assertTrue(decision_at_clock(grant(), LATER).allowed)

    def test_real_policy_stale_source_witness_stays_visible_in_2050(self):
        # Temporary original-source witness: remove/invert on owner fix.
        self.assertTrue(
            decision_at_clock(grant(revoked_by="fictional-operator"), LATER).allowed
        )

    def test_real_policy_expired_window_still_denies_in_2050(self):
        expired = grant(valid_until=NOW)
        self.assertFalse(decision_at_clock(expired, LATER).allowed)

    def test_explicit_revocation_denies_direct_current_check(self):
        revoked = grant(
            revoked_at=NOW - timedelta(minutes=10),
            revoked_by="fictional-operator",
            revocation_reason="fictional-customer-withdrew-consent",
        )
        self.assertFalse(revoked.is_current(NOW))
        self.assertTrue(revoked.is_revoked)

    def test_explicit_revocation_denies_real_target_active_policy(self):
        revoked = grant(
            revoked_at=NOW - timedelta(minutes=10),
            revoked_by="fictional-operator",
            revocation_reason="fictional-customer-withdrew-consent",
        )
        self.assertFalse(decision(revoked).allowed)

    def test_expired_canonical_grant_denies_without_revocation(self):
        expired = grant(valid_until=NOW - timedelta(seconds=1))
        self.assertFalse(expired.is_current(NOW))

    def test_future_canonical_grant_denies_without_revocation(self):
        future = grant(valid_from=NOW + timedelta(seconds=1))
        self.assertFalse(future.is_current(NOW))

    def test_mismatched_tenant_still_denied_with_stale_actor(self):
        stale = grant(revoked_by="fictional-revoker")
        self.assertFalse(decision(stale, client_id="different-fictional-client").allowed)

    def test_outside_asset_still_denied_with_stale_reason(self):
        stale = grant(revocation_reason="withdrawn")
        self.assertFalse(decision(stale, asset="outside-fixture.example.test").allowed)

    def test_risk_above_scope_still_denied_with_stale_actor(self):
        stale = grant(revoked_by="fictional-revoker")
        self.assertFalse(decision(stale, requested_risk=RiskLevel.ELEVATED).allowed)

    def test_direct_current_does_not_mutate_frozen_grant(self):
        stale = grant(revoked_by="fictional-revoker")
        before = (stale.revoked_at, stale.revoked_by, stale.revocation_reason)
        stale.is_current(NOW)
        after = (stale.revoked_at, stale.revoked_by, stale.revocation_reason)
        self.assertEqual(after, before)

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: actor is retained without tombstone
    def test_stale_revoker_without_timestamp_must_not_be_current(self):
        self.assertFalse(grant(revoked_by="fictional-revoker").is_current(NOW))

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: reason alone must revoke usability
    def test_stale_reason_without_timestamp_must_not_be_current(self):
        self.assertFalse(grant(revocation_reason="consent withdrawn").is_current(NOW))

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: both stale fields remain usable
    def test_stale_actor_and_reason_without_timestamp_must_not_be_current(self):
        self.assertFalse(
            grant(
                revoked_by="fictional-revoker",
                revocation_reason="consent withdrawn",
            ).is_current(NOW)
        )

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: actual policy currently permits actor
    def test_stale_revoker_must_not_authorize_target_active(self):
        self.assertFalse(decision(grant(revoked_by="fictional-revoker")).allowed)

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: actual policy currently permits reason
    def test_stale_reason_must_not_authorize_target_active(self):
        self.assertFalse(decision(grant(revocation_reason="withdrawn")).allowed)

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: actual policy currently permits both
    def test_stale_revoker_and_reason_must_not_authorize_target_active(self):
        self.assertFalse(
            decision(
                grant(
                    revoked_by="fictional-revoker",
                    revocation_reason="withdrawn",
                )
            ).allowed
        )

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: even blank actor is non-null provenance
    def test_blank_revoker_without_timestamp_must_fail_closed(self):
        self.assertFalse(grant(revoked_by="").is_current(NOW))

    @unittest.expectedFailure  # ORIGINAL SOURCE RED: even blank reason is non-null provenance
    def test_blank_reason_without_timestamp_must_fail_closed(self):
        self.assertFalse(grant(revocation_reason="").is_current(NOW))


if __name__ == "__main__":
    unittest.main()
