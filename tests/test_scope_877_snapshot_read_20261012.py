"""#877 W2: same-row tenant-gated, all-or-nothing real SQLite read proof."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.request_assets_snapshot_optin import (
    checked_get_assessment_request, checked_list_assessment_requests,
)


class RequestAssetSnapshotW2(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Path(temp.name) / "scope877w2.db"
        self.store = DomainStore(self.database)
        self.operator = AccessContext("lab-operator", Role.OPERATOR)
        alpha = self.store.create_client(self.operator, "Synthetic alpha")
        beta = self.store.create_client(self.operator, "Synthetic beta")
        self.a = AccessContext("lab-a", Role.CLIENT_ADMIN, alpha.client_id)
        self.b = AccessContext("lab-b", Role.CLIENT_ADMIN, beta.client_id)
        self.a_req = self.store.submit_assessment_request(
            self.a, ("alpha.example.test",), AssessmentMode.ANALYSIS_ONLY,
            RiskLevel.ANALYSIS_ONLY,
        )
        self.b_req = self.store.submit_assessment_request(
            self.b, ("beta.example.test",), AssessmentMode.ANALYSIS_ONLY,
            RiskLevel.ANALYSIS_ONLY,
        )

    def alter(self, request_id, raw):
        with sqlite3.connect(self.database) as con:
            con.execute(
                "UPDATE assessment_requests SET requested_assets_json=? "
                "WHERE request_id=?", (raw, request_id),
            )

    def snapshot(self):
        with sqlite3.connect(self.database) as con:
            return con.execute(
                "SELECT request_id,client_id,requested_assets_json FROM "
                "assessment_requests ORDER BY request_id"
            ).fetchall()

    def test_exact_single_selector_returns_existing_record(self):
        item = checked_get_assessment_request(
            self.store, self.a, self.a_req.request_id,
        )
        self.assertEqual(item.request_id, self.a_req.request_id)
        self.assertEqual(item.requested_assets, ("alpha.example.test",))
        self.assertEqual(self.snapshot()[0][1] in (
            self.a.client_id, self.b.client_id,
        ), True)

    def test_malformed_single_is_refused_on_same_row(self):
        for bad in ('{"alpha.example.test":1}', '"alpha.example.test"',
                    '[]', '["alpha.example.test",false]', '[" "]'):
            with self.subTest(bad=bad):
                self.alter(self.a_req.request_id, bad)
                prior = self.snapshot()
                with self.assertRaises(ValueError):
                    checked_get_assessment_request(
                        self.store, self.a, self.a_req.request_id,
                    )
                self.assertEqual(self.snapshot(), prior)

    def test_foreign_tenant_is_rejected_before_asset_json_decode(self):
        self.alter(self.a_req.request_id, '{"invalid":"assets"}')
        with patch(
            "lightup.request_assets_snapshot_optin.checked_requested_assets_json",
            side_effect=AssertionError("cross-tenant JSON decoded"),
        ) as validator:
            with self.assertRaises(TenantIsolationError):
                checked_get_assessment_request(
                    self.store, self.b, self.a_req.request_id,
                )
            validator.assert_not_called()

    def test_missing_request_raises_keyerror_without_allocation(self):
        with self.assertRaises(KeyError):
            checked_get_assessment_request(self.store, self.a, "missing-fixture")

    def test_invalid_identifier_fails_before_db_lookup(self):
        for bad in (None, 1, False, b"abc", "", ["abc"]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(ValueError):
                    checked_get_assessment_request(self.store, self.a, bad)

    def test_client_list_is_scoped_to_visible_tenant(self):
        a = checked_list_assessment_requests(self.store, self.a)
        b = checked_list_assessment_requests(self.store, self.b)
        self.assertEqual([x.request_id for x in a], [self.a_req.request_id])
        self.assertEqual([x.request_id for x in b], [self.b_req.request_id])

    def test_operator_unscoped_list_includes_two_canonical_rows(self):
        rows = checked_list_assessment_requests(self.store, self.operator)
        self.assertEqual(
            {x.request_id for x in rows},
            {self.a_req.request_id, self.b_req.request_id},
        )

    def test_operator_explicit_client_scope_filters_visible_rows(self):
        rows = checked_list_assessment_requests(
            self.store, self.operator, client_id=self.a.client_id,
        )
        self.assertEqual([x.request_id for x in rows], [self.a_req.request_id])

    def test_cross_tenant_list_filter_fails_before_query(self):
        with self.assertRaises(TenantIsolationError):
            checked_list_assessment_requests(
                self.store, self.a, client_id=self.b.client_id,
            )

    def test_corrupt_other_tenant_row_does_not_block_own_scoped_list(self):
        self.alter(self.b_req.request_id, '"not an array"')
        rows = checked_list_assessment_requests(self.store, self.a)
        self.assertEqual([x.request_id for x in rows], [self.a_req.request_id])

    def test_corrupt_other_tenant_row_makes_operator_full_list_fail_closed(self):
        self.alter(self.b_req.request_id, '"not an array"')
        with self.assertRaises(ValueError):
            checked_list_assessment_requests(self.store, self.operator)

    def test_corrupt_first_or_last_visible_row_refuses_whole_batch(self):
        extra = self.store.submit_assessment_request(
            self.a, ("extra.example.test",), AssessmentMode.ANALYSIS_ONLY,
            RiskLevel.ANALYSIS_ONLY,
        )
        original = self.snapshot()
        for request_id in (self.a_req.request_id, extra.request_id):
            with self.subTest(request_id=request_id):
                self.alter(request_id, '{"not":"an array"}')
                with self.assertRaises(ValueError):
                    checked_list_assessment_requests(self.store, self.a)
                # Source would otherwise silently turn the malformed object
                # into a tuple of keys; optional reader must never do so.
                with sqlite3.connect(self.database) as con:
                    con.execute(
                        "UPDATE assessment_requests SET requested_assets_json=? "
                        "WHERE request_id=?",
                        ('["alpha.example.test"]' if request_id ==
                         self.a_req.request_id else '["extra.example.test"]',
                         request_id),
                    )
        self.assertEqual(self.snapshot(), original)

    def test_absent_rows_return_empty_list_without_side_effects(self):
        with sqlite3.connect(self.database) as con:
            con.execute("DELETE FROM assessment_requests")
        self.assertEqual(checked_list_assessment_requests(self.store, self.a), [])
        self.assertEqual(checked_list_assessment_requests(self.store, self.operator), [])

    def test_corrupt_single_rejection_preserves_entire_durable_table(self):
        self.alter(self.a_req.request_id, '["alpha.example.test",null]')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            checked_get_assessment_request(self.store, self.a, self.a_req.request_id)
        self.assertEqual(self.snapshot(), before)

    def test_no_authorization_grants_or_engagements_are_created(self):
        checked_get_assessment_request(self.store, self.a, self.a_req.request_id)
        checked_list_assessment_requests(self.store, self.operator)
        with sqlite3.connect(self.database) as con:
            g = con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]
            e = con.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
        self.assertEqual((g, e), (0, 0))


if __name__ == "__main__":
    unittest.main()
