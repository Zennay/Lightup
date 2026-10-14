"""Offline real grant model tests for all-or-nothing multi-tenant reviews."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_revision_batch_review import review_grant_revision_batch


def grant(**overrides):
    values = {
        "grant_id": "g1",
        "client_id": "client1",
        "engagement_id": "eng1",
        "approved_by": "operator1",
        "reference": "ref1",
        "scope": ScopeDefinition(
            assets=("a.example.test", "b.example.test"),
            excluded_assets=("b.example.test",),
            allowed_capabilities=("headers", "tls"),
            max_risk=RiskLevel.STANDARD,
        ),
        "valid_from": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "valid_until": datetime(2026, 10, 2, tzinfo=timezone.utc),
        "recurring_retest_allowed": True,
    }
    values.update(overrides)
    return AuthorizationGrant(**values)



class GrantRevisionBatchReviewTests(unittest.TestCase):
    def make_pair(self, *, grant_id, client, assets, risk=None):
        previous = grant(
            grant_id=grant_id, client_id=client,
            scope=replace(grant().scope, assets=assets, excluded_assets=(),
                          allowed_capabilities=("headers", "tls")),
        )
        current = replace(
            previous,
            scope=replace(previous.scope, allowed_capabilities=("headers",)),
        )
        if risk is not None:
            current = replace(current, scope=replace(current.scope, max_risk=risk))
        return previous, current

    def test_two_disjoint_tenants_reviewed_without_authority(self):
        pairs = (
            self.make_pair(grant_id="g1", client="client1", assets=("one.example.test",)),
            self.make_pair(grant_id="g2", client="client2", assets=("two.example.test",)),
        )
        receipt = review_grant_revision_batch(pairs)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertEqual(receipt.reviewed_count, 2)
        self.assertEqual(receipt.narrowed_count, 2)
        for name in ("authorization_verified", "permit_issued", "execution_enabled",
                     "merge_approved", "release_approved"):
            self.assertIs(getattr(receipt, name), False)

    def test_cross_tenant_overlap_atomically_held(self):
        pairs = (
            self.make_pair(grant_id="g1", client="client1", assets=("shared.example.test",)),
            self.make_pair(grant_id="g2", client="client2", assets=("shared.example.test",)),
        )
        r = review_grant_revision_batch(pairs)
        self.assertEqual(r.verdict, "HOLD")
        self.assertEqual(r.reason_code, "cross_tenant_asset_overlap")
        self.assertEqual(r.reviewed_count, 0)
        self.assertEqual(r.narrowed_count, 0)

    def test_duplicate_grant_id_denied(self):
        pair = self.make_pair(grant_id="g1", client="client1", assets=("one.example.test",))
        r = review_grant_revision_batch((pair, pair))
        self.assertEqual(r.reason_code, "duplicate_grant_id")
        self.assertEqual(r.reviewed_count, 0)

    def test_late_risk_escalation_zeros_earlier_review(self):
        first = self.make_pair(grant_id="g1", client="client1", assets=("one.example.test",))
        second = self.make_pair(grant_id="g2", client="client2", assets=("two.example.test",))
        unsafe = (second[0], replace(second[1], scope=replace(
            second[1].scope, max_risk=5)))
        r = review_grant_revision_batch((first, unsafe))
        self.assertEqual(r.reason_code, "revision_held")
        self.assertEqual(r.reviewed_count, 0)
        self.assertEqual(r.narrowed_count, 0)

    def test_same_tenant_can_hold_distinct_grants_for_same_asset(self):
        pairs = (
            self.make_pair(grant_id="g1", client="client1", assets=("shared.example.test",)),
            self.make_pair(grant_id="g2", client="client1", assets=("shared.example.test",)),
        )
        self.assertEqual(review_grant_revision_batch(pairs).verdict, "REVIEW_ONLY")

    def test_excluded_assets_do_not_count_as_cross_tenant_active(self):
        first = self.make_pair(grant_id="g1", client="client1", assets=("shared.example.test",))
        second = self.make_pair(grant_id="g2", client="client2", assets=("shared.example.test",))
        old, new = first
        first = (
            replace(old, scope=replace(old.scope, excluded_assets=("shared.example.test",))),
            replace(new, scope=replace(new.scope, excluded_assets=("shared.example.test",))),
        )
        self.assertEqual(review_grant_revision_batch((first, second)).verdict, "REVIEW_ONLY")

    def test_empty_oversized_and_malformed_batch_shapes_hold(self):
        for malformed in (None, [], (), tuple([("x", "y")] * 33), (1,), ((1, 2, 3),)):
            with self.subTest(malformed=str(type(malformed))):
                r = review_grant_revision_batch(malformed)
                self.assertEqual(r.verdict, "HOLD")
                self.assertEqual(r.reviewed_count, 0)
                self.assertFalse(r.execution_enabled)

    def test_duplicate_tenants_dont_combine_into_new_privilege(self):
        a = self.make_pair(grant_id="g1", client="client1", assets=("one.example.test",))
        b = self.make_pair(grant_id="g2", client="client1", assets=("two.example.test",))
        self.assertEqual(review_grant_revision_batch((a, b)).verdict, "REVIEW_ONLY")

    def test_no_network_db_and_no_private_asset_echo(self):
        secret = "private-host-123.example.test"
        a = self.make_pair(grant_id="g1", client="client1", assets=(secret,))
        b = self.make_pair(grant_id="g2", client="client2", assets=(secret,))
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("database forbidden")):
            receipt = review_grant_revision_batch((a, b))
        self.assertEqual(receipt.verdict, "HOLD")
        self.assertNotIn(secret, repr(receipt))
        self.assertFalse(receipt.authorization_verified)


if __name__ == "__main__":
    unittest.main()
