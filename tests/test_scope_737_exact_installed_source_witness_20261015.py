"""#737 precise installed-source witness guards (temporarily unsafe by design).

These ORDINARY PASS tests deliberately characterize the existing original
AuthorizationGrant/ExecutionPolicy BUG with fake grants, no IO, no handlers.
They prevent generic expectedFailure from hiding TypeErrors / other errors
instead of the known, exact, wrong source result. They MUST be inverted or
retired by #100 source-owner when the real source is repaired.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


NOW = datetime(2050, 1, 1, 12, 0, tzinfo=timezone.utc)
VALID_FROM = datetime(2000, 1, 1, tzinfo=timezone.utc)
VALID_UNTIL = datetime(9999, 12, 31, tzinfo=timezone.utc)
ASSET = "fictional-source-witness.example.test"
CAPABILITY = "fixture-inert-baseline"


def grant(*, revoked_by=None, revocation_reason=None):
    return AuthorizationGrant(
        grant_id="fictional-737-witness",
        client_id="fictional-client",
        engagement_id="fictional-engagement",
        approved_by="fictional-reviewer",
        reference="synthetic-signed-review",
        scope=ScopeDefinition(
            assets=(ASSET,),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(CAPABILITY,),
        ),
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        revoked_at=None,
        revoked_by=revoked_by,
        revocation_reason=revocation_reason,
    )


def real_policy(g):
    return ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset=ASSET,
            capability_id=CAPABILITY,
            requested_risk=RiskLevel.STANDARD,
            authorization=g,
            client_id=g.client_id,
            engagement_id=g.engagement_id,
        )
    )


class ExactUnsafeSourceWitnessTests(unittest.TestCase):
    def test_clean_grant_is_current_at_fixed_2050(self):
        self.assertIs(grant().is_current(NOW), True)

    def test_stale_actor_current_is_exact_unsafe_true_not_error(self):
        self.assertIs(grant(revoked_by="fictional-actor").is_current(NOW), True)

    def test_stale_reason_current_is_exact_unsafe_true_not_error(self):
        self.assertIs(grant(revocation_reason="fixture-withdrawn").is_current(NOW), True)

    def test_actor_and_reason_current_is_exact_unsafe_true_not_error(self):
        self.assertIs(
            grant(revoked_by="fictional-actor", revocation_reason="fixture-withdrawn").is_current(NOW),
            True,
        )

    def test_blank_actor_current_is_exact_unsafe_true_not_error(self):
        self.assertIs(grant(revoked_by="").is_current(NOW), True)

    def test_blank_reason_current_is_exact_unsafe_true_not_error(self):
        self.assertIs(grant(revocation_reason="").is_current(NOW), True)

    def test_explicitly_stale_actor_keeps_fictional_target_policy_unsafe(self):
        # Live system clock is safely inside the enormous synthetic window.
        result = real_policy(grant(revoked_by="fictional-actor"))
        self.assertIs(result.allowed, True)
        self.assertEqual(result.reason, "authorized active assessment")

    def test_explicitly_stale_reason_keeps_fictional_target_policy_unsafe(self):
        result = real_policy(grant(revocation_reason="fixture-withdrawn"))
        self.assertIs(result.allowed, True)
        self.assertEqual(result.reason, "authorized active assessment")

    def test_actor_and_reason_keeps_fictional_target_policy_unsafe(self):
        result = real_policy(grant(
            revoked_by="fictional-actor", revocation_reason="fixture-withdrawn"
        ))
        self.assertIs(result.allowed, True)
        self.assertEqual(result.reason, "authorized active assessment")

    def test_explicitly_clean_policy_remains_ordinary_allow_control(self):
        result = real_policy(grant())
        self.assertIs(result.allowed, True)
        self.assertEqual(result.reason, "authorized active assessment")

    def test_cross_client_mismatch_still_denied_even_if_revocation_stale(self):
        g = grant(revoked_by="fictional-actor")
        request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset=ASSET,
            capability_id=CAPABILITY,
            requested_risk=RiskLevel.STANDARD,
            authorization=g,
            client_id="another-fictional-client",
            engagement_id=g.engagement_id,
        )
        result = ExecutionPolicy().decide(request)
        self.assertIs(result.allowed, False)
        self.assertEqual(result.reason, "authorization client does not match execution client")

    def test_no_state_mutation_across_unsafe_source_check(self):
        g = grant(revoked_by="fictional-actor", revocation_reason="fixture-withdrawn")
        before = (g.revoked_at, g.revoked_by, g.revocation_reason, g.scope)
        self.assertIs(g.is_current(NOW), True)
        self.assertEqual((g.revoked_at, g.revoked_by, g.revocation_reason, g.scope), before)


if __name__ == "__main__":
    unittest.main()
