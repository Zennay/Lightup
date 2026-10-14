"""Synthetic all-or-nothing multi-grant history review regressions."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_revision_history_batch_review import review_grant_history_batch


NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
LATER = datetime(2026, 11, 2, tzinfo=timezone.utc)


def make_history(grant_id: str, client: str, asset: str):
    baseline = AuthorizationGrant(
        grant_id=grant_id, client_id=client, engagement_id="eng1",
        approved_by="operator1", reference="synthetic-only",
        scope=ScopeDefinition(assets=(asset,), max_risk=RiskLevel.STANDARD,
                              excluded_assets=(), allowed_capabilities=("headers", "tls")),
        valid_from=NOW, valid_until=LATER, recurring_retest_allowed=False,
    )
    proposed = replace(
        baseline,
        scope=replace(baseline.scope, allowed_capabilities=("headers",)),
    )
    return baseline, proposed


class MultiHistoryReviewTests(unittest.TestCase):
    def assert_held(self, histories, reason=None):
        receipt = review_grant_history_batch(histories)
        self.assertEqual(receipt.verdict, "HOLD")
        if reason:
            self.assertEqual(receipt.reason_code, reason)
        self.assertEqual(receipt.reviewed_histories, 0)
        self.assertEqual(receipt.reviewed_transitions, 0)
        self.assertEqual(receipt.narrowed_dimensions, 0)
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.permit_issued)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.merge_approved)
        self.assertFalse(receipt.release_approved)
        return receipt

    def test_two_disjoint_declared_tenants_have_only_review(self):
        histories = (
            make_history("g1", "tenant1", "one.example.test"),
            make_history("g2", "tenant2", "two.example.test"),
        )
        receipt = review_grant_history_batch(histories)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertEqual(receipt.reviewed_histories, 2)
        self.assertEqual(receipt.reviewed_transitions, 2)
        self.assertEqual(receipt.narrowed_dimensions, 2)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.authorization_verified)

    def test_late_widening_zeros_entire_history_batch(self):
        safe = make_history("g1", "tenant1", "one.example.test")
        old, _ = make_history("g2", "tenant2", "two.example.test")
        widened = replace(old, scope=replace(
            old.scope, assets=("two.example.test", "three.example.test")))
        self.assert_held((safe, (old, widened)), "history_held")

    def test_history_hidden_transient_widening_is_not_clean(self):
        safe = make_history("g1", "tenant1", "one.example.test")
        original, final = make_history("g2", "tenant2", "two.example.test")
        transient = replace(original, scope=replace(
            original.scope, assets=("two.example.test", "other.example.test")))
        self.assert_held((safe, (original, transient, final)), "history_held")

    def test_duplicate_grant_identifiers_across_histories_are_held(self):
        h1 = make_history("same-id", "tenant1", "one.example.test")
        h2 = make_history("same-id", "tenant2", "two.example.test")
        self.assert_held((h1, h2), "cross_history_coherence_held")

    def test_same_active_asset_cross_tenant_is_held(self):
        h1 = make_history("g1", "tenant1", "shared.example.test")
        h2 = make_history("g2", "tenant2", "shared.example.test")
        self.assert_held((h1, h2), "cross_history_coherence_held")

    def test_network_literal_cross_tenant_is_held(self):
        h1 = make_history("g1", "tenant1", "192.168.1.0/24")
        h2 = make_history("g2", "tenant2", "192.168.1.3")
        self.assert_held((h1, h2), "cross_history_coherence_held")

    def test_single_grant_history_with_network_shape_remains_non_authorizing(self):
        history = make_history("g1", "tenant1", "192.168.1.0/24")
        receipt = review_grant_history_batch((history,))
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertFalse(receipt.execution_enabled)

    def test_bad_history_lengths_and_types_are_held(self):
        for data in (
            None, [], (), tuple([make_history("g", "tenant", "a.example.test")] * 17),
            (1,), ((1, 2),), ((make_history("g1", "tenant1", "one.example.test"),),),
        ):
            with self.subTest(data_type=type(data)):
                self.assert_held(data)

    def test_up_to_sixteen_distinct_tenants_reviewable_without_permit(self):
        histories = tuple(
            make_history(f"g{i}", f"tenant{i}", f"{i}.example.test")
            for i in range(16)
        )
        receipt = review_grant_history_batch(histories)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertEqual(receipt.reviewed_histories, 16)
        self.assertEqual(receipt.reviewed_transitions, 16)
        self.assertFalse(receipt.release_approved)

    def test_16th_bad_tenant_claim_yields_atomic_hold(self):
        histories = tuple(
            make_history(f"g{i}", f"tenant{i}", f"{i}.example.test")
            for i in range(15)
        ) + (make_history("g15", "tenant15", "0.example.test"),)
        self.assert_held(histories, "cross_history_coherence_held")

    def test_network_database_absence_and_opaque_hold(self):
        h1 = make_history("g1", "tenant1", "private.example.test")
        h2 = make_history("g2", "tenant2", "private.example.test")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("database forbidden")):
            result = self.assert_held((h1, h2))
        self.assertNotIn("private.example.test", repr(result))


if __name__ == "__main__":
    unittest.main()
