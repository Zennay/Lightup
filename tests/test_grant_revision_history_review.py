"""Synthetic original-model regressions for atomic grant history review."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_revision_history_review import review_grant_history


T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
T1 = datetime(2026, 11, 10, tzinfo=timezone.utc)


def grant(**fields):
    defaults = dict(
        grant_id="g1",
        client_id="tenant1",
        engagement_id="eng1",
        approved_by="operator1",
        reference="offline-ref",
        scope=ScopeDefinition(
            assets=("a.example.test", "b.example.test", "c.example.test"),
            excluded_assets=(),
            allowed_capabilities=("headers", "tls", "inventory"),
            max_risk=RiskLevel.STANDARD,
        ),
        valid_from=T0,
        valid_until=T1,
        recurring_retest_allowed=True,
    )
    defaults.update(fields)
    return AuthorizationGrant(**defaults)


class GrantHistoryTests(unittest.TestCase):
    def assert_denied(self, snapshots, reason=None):
        result = review_grant_history(snapshots)
        self.assertEqual(result.verdict, "HOLD")
        if reason:
            self.assertEqual(result.reason_code, reason)
        self.assertEqual(result.version_count, 0)
        self.assertEqual(result.reviewed_transitions, 0)
        self.assertEqual(result.narrowed_fields, ())
        for name in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved",
        ):
            self.assertIs(getattr(result, name), False)
        return result

    def test_three_valid_narrowings_are_review_only(self):
        v0 = grant()
        v1 = replace(v0, scope=replace(v0.scope, assets=("a.example.test", "b.example.test")))
        v2 = replace(
            v1, scope=replace(v1.scope, allowed_capabilities=("headers",),
                              max_risk=RiskLevel.LOW_IMPACT),
            valid_from=T0 + timedelta(days=1), valid_until=T1 - timedelta(days=1),
            recurring_retest_allowed=False,
        )
        result = review_grant_history((v0, v1, v2))
        self.assertEqual(result.verdict, "REVIEW_ONLY")
        self.assertEqual(result.version_count, 3)
        self.assertEqual(result.reviewed_transitions, 2)
        self.assertEqual(result.narrowed_fields,
                         ("assets", "capabilities", "recurring_retest", "risk", "window"))
        self.assertFalse(result.authorization_verified)
        self.assertFalse(result.execution_enabled)

    def test_transient_asset_widening_then_narrowing_is_held(self):
        v0 = grant()
        temporary = replace(v0, scope=replace(
            v0.scope,
            assets=("a.example.test", "b.example.test", "c.example.test", "d.example.test"),
        ))
        last = replace(v0, scope=replace(v0.scope, assets=("a.example.test",)))
        self.assert_denied((v0, temporary, last), "transition_held")

    def test_transient_risk_widening_then_reversion_is_held(self):
        v0 = grant(scope=replace(grant().scope, max_risk=RiskLevel.LOW_IMPACT))
        temporary = replace(v0, scope=replace(v0.scope, max_risk=RiskLevel.STANDARD))
        final = replace(v0, scope=replace(v0.scope, max_risk=RiskLevel.PASSIVE))
        self.assert_denied((v0, temporary, final), "transition_held")

    def test_transient_utc_widening_then_reversion_is_held(self):
        v0 = grant()
        temporary = replace(v0, valid_until=T1 + timedelta(seconds=1))
        final = replace(v0, valid_until=T1 - timedelta(seconds=1))
        self.assert_denied((v0, temporary, final), "transition_held")

    def test_transient_capability_wildcard_then_narrowing_is_held(self):
        v0 = grant()
        temporary = replace(v0, scope=replace(v0.scope, allowed_capabilities=()))
        final = replace(v0, scope=replace(v0.scope, allowed_capabilities=("headers",)))
        self.assert_denied((v0, temporary, final), "transition_held")

    def test_transient_retest_authority_then_reversion_is_held(self):
        v0 = grant(recurring_retest_allowed=False)
        temporary = replace(v0, recurring_retest_allowed=True)
        self.assert_denied((v0, temporary, v0), "transition_held")

    def test_transient_tenant_reassignment_then_reversion_is_held(self):
        v0 = grant()
        temporary = replace(v0, client_id="tenant2")
        final = replace(v0, scope=replace(v0.scope, assets=("a.example.test",)))
        self.assert_denied((v0, temporary, final), "transition_held")

    def test_duplicate_and_noop_revisions_are_held(self):
        v0 = grant()
        v1 = replace(v0, scope=replace(v0.scope, assets=("a.example.test",)))
        for history in ((v0, v0), (v0, v1, v1), (v0, v0, v1)):
            with self.subTest(history_len=len(history)):
                self.assert_denied(history, "duplicate_or_noop_version")

    def test_exclusion_removal_alone_is_not_a_narrowing(self):
        initial = grant(scope=replace(grant().scope, excluded_assets=("b.example.test",)))
        later = replace(initial, scope=replace(initial.scope, excluded_assets=()))
        self.assert_denied((initial, later), "transition_held")

    def test_add_exclusion_and_remove_asset_are_valid_narrowings(self):
        initial = grant()
        v1 = replace(initial, scope=replace(initial.scope, excluded_assets=("c.example.test",)))
        v2 = replace(v1, scope=replace(v1.scope, assets=("a.example.test", "b.example.test"),
                                       excluded_assets=()))
        self.assertEqual(review_grant_history((initial, v1, v2)).verdict, "REVIEW_ONLY")

    def test_history_rejects_bad_shape_and_forged_class(self):
        class FakeGrant(AuthorizationGrant):
            pass
        for history in (None, [], (), (grant(),), tuple(grant() for _ in range(9)),
                        (grant(), FakeGrant(**vars(grant()))), ((grant(), grant()),)):
            with self.subTest(value_type=type(history)):
                self.assert_denied(history)

    def test_eight_versions_seven_real_narrowings(self):
        v0 = grant()
        versions = [v0]
        for asset_count in (2, 1):
            previous = versions[-1]
            versions.append(replace(previous, scope=replace(
                previous.scope, assets=previous.scope.assets[:asset_count])))
        for capabilities in (("headers", "tls"), ("headers",)):
            previous = versions[-1]
            versions.append(replace(previous, scope=replace(
                previous.scope, allowed_capabilities=capabilities)))
        previous = versions[-1]
        versions.append(replace(previous, scope=replace(
            previous.scope, max_risk=RiskLevel.LOW_IMPACT)))
        previous = versions[-1]
        versions.append(replace(previous, valid_until=T1 - timedelta(hours=2)))
        previous = versions[-1]
        versions.append(replace(previous, recurring_retest_allowed=False))
        self.assertEqual(len(versions), 8)
        result = review_grant_history(tuple(versions))
        self.assertEqual(result.verdict, "REVIEW_ONLY")
        self.assertEqual(result.reviewed_transitions, 7)

    def test_temporary_malformed_version_cannot_be_hidden(self):
        initial = grant()
        middle = replace(initial, scope=replace(initial.scope, assets=("A.example.test",)))
        final = replace(initial, scope=replace(initial.scope, assets=("a.example.test",)))
        self.assert_denied((initial, middle, final), "transition_held")

    def test_privacy_and_no_network_or_database(self):
        initial = grant(reference="secret-private-reference")
        expanded = replace(initial, scope=replace(
            initial.scope,
            assets=initial.scope.assets + ("private-customer.example.test",)))
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("db forbidden")):
            receipt = self.assert_denied((initial, expanded))
        self.assertNotIn("secret-private-reference", repr(receipt))
        self.assertNotIn("private-customer", repr(receipt))


if __name__ == "__main__":
    unittest.main()
