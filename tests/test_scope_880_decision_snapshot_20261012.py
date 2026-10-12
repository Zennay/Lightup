"""#880 W2: genuine SQLite same-snapshot decision provenance gate tests."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, RequestStatus, Role, TenantIsolationError
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.request_decision_snapshot_optin import (
    checked_get_decision_request, checked_list_decision_requests,
)


class RequestDecisionSnapshotW2(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "scope880w2.db"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("lab-op", Role.OPERATOR)
        a = self.store.create_client(self.operator, "Synthetic 880 A")
        b = self.store.create_client(self.operator, "Synthetic 880 B")
        self.a = AccessContext("lab-a", Role.CLIENT_ADMIN, a.client_id)
        self.b = AccessContext("lab-b", Role.CLIENT_ADMIN, b.client_id)
        self.ra = self.store.submit_assessment_request(
            self.a, ("a.example.test",), AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
        )
        self.rb = self.store.submit_assessment_request(
            self.b, ("b.example.test",), AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
        )

    def tamper(self, rid, status, actor, when):
        with sqlite3.connect(self.path) as con:
            con.execute(
                "UPDATE assessment_requests SET status=?,decided_by=?,decided_at=? "
                "WHERE request_id=?", (status, actor, when, rid)
            )

    def rows(self):
        with sqlite3.connect(self.path) as con:
            return con.execute(
                "SELECT request_id,status,decided_by,decided_at FROM "
                "assessment_requests ORDER BY request_id"
            ).fetchall()

    def test_canonical_submitted_get_is_original_record(self):
        got = checked_get_decision_request(self.store, self.a, self.ra.request_id)
        self.assertEqual(got.request_id, self.ra.request_id)
        self.assertIs(got.status, RequestStatus.SUBMITTED)
        self.assertIsNone(got.decided_by)

    def test_canonical_approved_and_rejected_roundtrip(self):
        self.store.review_assessment_request(self.operator, self.ra.request_id, True)
        self.store.review_assessment_request(self.operator, self.rb.request_id, False)
        a = checked_get_decision_request(self.store, self.a, self.ra.request_id)
        b = checked_get_decision_request(self.store, self.b, self.rb.request_id)
        self.assertIs(a.status, RequestStatus.APPROVED)
        self.assertIs(b.status, RequestStatus.REJECTED)
        self.assertEqual(a.decided_by, self.operator.user_id)
        self.assertEqual(b.decided_by, self.operator.user_id)

    def test_corrupt_single_never_changes_durable_decision_fields(self):
        self.tamper(self.ra.request_id, "approved", None, None)
        before = self.rows()
        with self.assertRaises(ValueError):
            checked_get_decision_request(self.store, self.a, self.ra.request_id)
        self.assertEqual(self.rows(), before)

    def test_malformed_actor_and_decision_timestamps_denied(self):
        for status, actor, when in (
            ("approved", None, "2026-10-12T22:00:00+00:00"),
            ("approved", "  ", "2026-10-12T22:00:00+00:00"),
            ("approved", "lab-op", "not-a-date"),
            ("rejected", "lab-op", None),
            ("rejected", "lab-op", "2026-10-12T22:00:00"),
            ("submitted", "lab-op", "2026-10-12T22:00:00+00:00"),
            ("under_review", None, "2026-10-12T22:00:00+00:00"),
        ):
            with self.subTest(status=status, actor=actor, when=when):
                self.tamper(self.ra.request_id, status, actor, when)
                before = self.rows()
                with self.assertRaises(ValueError):
                    checked_get_decision_request(self.store, self.a, self.ra.request_id)
                self.assertEqual(self.rows(), before)

    def test_foreign_tenant_denied_before_source_row_projection(self):
        self.tamper(self.ra.request_id, "approved", None, None)
        with patch("lightup.request_decision_snapshot_optin._checked_row",
                   side_effect=AssertionError("foreign row decoded")) as decode:
            with self.assertRaises(TenantIsolationError):
                checked_get_decision_request(self.store, self.b, self.ra.request_id)
            decode.assert_not_called()

    def test_operator_unscoped_get_handles_valid_audit_row(self):
        got = checked_get_decision_request(self.store, self.operator, self.ra.request_id)
        self.assertEqual(got.request_id, self.ra.request_id)

    def test_invalid_or_missing_ids_refused(self):
        for bad in (None, "", 0, False, [], {}, b"abc"):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(ValueError):
                checked_get_decision_request(self.store, self.a, bad)
        with self.assertRaises(KeyError):
            checked_get_decision_request(self.store, self.a, "missing")

    def test_client_list_never_exposes_foreign_row(self):
        self.assertEqual(
            [x.request_id for x in checked_list_decision_requests(self.store, self.a)],
            [self.ra.request_id],
        )
        self.assertEqual(
            [x.request_id for x in checked_list_decision_requests(self.store, self.b)],
            [self.rb.request_id],
        )

    def test_cross_tenant_list_filter_denied(self):
        with self.assertRaises(TenantIsolationError):
            checked_list_decision_requests(self.store, self.a, client_id=self.b.client_id)

    def test_operator_filtered_list_and_unfiltered_list_match(self):
        all_records = checked_list_decision_requests(self.store, self.operator)
        self.assertEqual(
            {x.request_id for x in all_records},
            {self.ra.request_id, self.rb.request_id},
        )
        a_only = checked_list_decision_requests(
            self.store, self.operator, client_id=self.a.client_id,
        )
        self.assertEqual([x.request_id for x in a_only], [self.ra.request_id])

    def test_corrupt_other_tenant_row_does_not_block_own_list(self):
        self.tamper(self.rb.request_id, "approved", None, None)
        self.assertEqual(
            [x.request_id for x in checked_list_decision_requests(self.store, self.a)],
            [self.ra.request_id],
        )

    def test_corrupt_other_tenant_row_denies_operator_unfiltered_list(self):
        self.tamper(self.rb.request_id, "approved", None, None)
        before = self.rows()
        with self.assertRaises(ValueError):
            checked_list_decision_requests(self.store, self.operator)
        self.assertEqual(self.rows(), before)

    def test_corrupt_later_row_denies_entire_visible_batch(self):
        extra = self.store.submit_assessment_request(
            self.a, ("extra.example.test",),
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
        )
        self.tamper(extra.request_id, "rejected", "lab-op", None)
        with self.assertRaises(ValueError):
            checked_list_decision_requests(self.store, self.a)
        self.assertEqual(self.store.get_assessment_request(
            self.a, self.ra.request_id,
        ).status, RequestStatus.SUBMITTED)

    def test_no_grant_or_engagement_side_effects(self):
        checked_get_decision_request(self.store, self.a, self.ra.request_id)
        checked_list_decision_requests(self.store, self.operator)
        with sqlite3.connect(self.path) as con:
            grants = con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]
            engagements = con.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
        self.assertEqual((grants, engagements), (0, 0))

    def test_list_empty_after_deleting_all_synthetic_fixture_rows(self):
        with sqlite3.connect(self.path) as con:
            con.execute("DELETE FROM assessment_requests")
        self.assertEqual(checked_list_decision_requests(self.store, self.operator), [])
        self.assertEqual(checked_list_decision_requests(self.store, self.a), [])


if __name__ == "__main__":
    unittest.main()
