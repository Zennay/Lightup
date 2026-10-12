"""#880: real disposable SQLite decision-provenance acceptance.

Five expected RED tests target unmodified DomainStore readers. The optional
coherence validator is non-authorizing, never installed, and read-only.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from lightup.domain import (
    AccessContext, DomainStore, RequestStatus, Role, TenantIsolationError,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.request_decision_provenance_optin import (
    checked_request_decision_provenance,
)


class DecisionProvenanceIssue880(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = Path(folder.name) / "scope880.db"
        self.store = DomainStore(self.db)
        self.op = AccessContext("synthetic-reviewer", Role.OPERATOR)
        c = self.store.create_client(self.op, "Synthetic A")
        foreign = self.store.create_client(self.op, "Synthetic B")
        self.client = AccessContext("synthetic-requester", Role.CLIENT_ADMIN, c.client_id)
        self.foreign = AccessContext("foreign-requester", Role.CLIENT_ADMIN, foreign.client_id)
        self.record = self.store.submit_assessment_request(
            self.client, ("scope880.example.test",), AssessmentMode.ANALYSIS_ONLY,
            RiskLevel.ANALYSIS_ONLY, "synthetic, analysis-only",
        )

    def snapshot(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute(
                "SELECT status,decided_by,decided_at FROM assessment_requests WHERE request_id=?",
                (self.record.request_id,),
            ).fetchone()

    def corrupt(self, status, actor, stamp):
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE assessment_requests SET status=?,decided_by=?,decided_at=? "
                "WHERE request_id=?",
                (status, actor, stamp, self.record.request_id),
            )

    def get(self):
        return self.store.get_assessment_request(self.op, self.record.request_id)

    @unittest.expectedFailure
    def test_red_approved_missing_actor_default_reader_must_refuse(self):
        self.corrupt("approved", None, datetime.now(timezone.utc).isoformat())
        with self.assertRaises(ValueError):
            self.get()

    @unittest.expectedFailure
    def test_red_rejected_missing_time_default_reader_must_refuse(self):
        self.corrupt("rejected", self.op.user_id, None)
        with self.assertRaises(ValueError):
            self.get()

    @unittest.expectedFailure
    def test_red_submitted_with_stale_decision_default_reader_must_refuse(self):
        self.corrupt("submitted", self.op.user_id, datetime.now(timezone.utc).isoformat())
        with self.assertRaises(ValueError):
            self.get()

    @unittest.expectedFailure
    def test_red_under_review_with_stale_actor_default_reader_must_refuse(self):
        self.corrupt("under_review", self.op.user_id, None)
        with self.assertRaises(ValueError):
            self.get()

    @unittest.expectedFailure
    def test_red_approved_malformed_decision_time_default_reader_must_refuse(self):
        self.corrupt("approved", self.op.user_id, "not-an-iso-timestamp")
        with self.assertRaises(ValueError):
            self.get()

    @unittest.expectedFailure
    def test_red_approved_naive_decision_time_default_reader_must_refuse(self):
        self.corrupt("approved", self.op.user_id, "2026-10-12T21:00:00")
        with self.assertRaises(ValueError):
            self.get()

    def test_valid_submitted_is_not_decided(self):
        loaded = self.get()
        self.assertIs(loaded.status, RequestStatus.SUBMITTED)
        self.assertIsNone(loaded.decided_by)
        self.assertIsNone(loaded.decided_at)
        self.assertIs(checked_request_decision_provenance(loaded), loaded)

    def test_valid_under_review_without_decision_is_open(self):
        self.corrupt("under_review", None, None)
        loaded = self.get()
        self.assertIs(loaded.status, RequestStatus.UNDER_REVIEW)
        self.assertIs(checked_request_decision_provenance(loaded), loaded)

    def test_real_approved_request_roundtrip(self):
        approved = self.store.review_assessment_request(
            self.op, self.record.request_id, True,
        )
        self.assertIs(approved.status, RequestStatus.APPROVED)
        loaded = self.get()
        self.assertIs(checked_request_decision_provenance(loaded), loaded)
        self.assertEqual(loaded.decided_by, self.op.user_id)

    def test_real_rejected_request_roundtrip(self):
        denied = self.store.review_assessment_request(
            self.op, self.record.request_id, False,
        )
        self.assertIs(denied.status, RequestStatus.REJECTED)
        loaded = self.get()
        self.assertIs(checked_request_decision_provenance(loaded), loaded)

    def test_optin_rejects_corrupt_durable_tuples_without_mutation(self):
        cases = (
            ("approved", None, datetime.now(timezone.utc).isoformat()),
            ("rejected", self.op.user_id, None),
            ("approved", "   ", datetime.now(timezone.utc).isoformat()),
            ("approved", self.op.user_id, "bad-date"),
            ("approved", self.op.user_id, "2026-10-12T21:00:00"),
            ("submitted", self.op.user_id, datetime.now(timezone.utc).isoformat()),
            ("under_review", None, datetime.now(timezone.utc).isoformat()),
        )
        for status, actor, stamp in cases:
            with self.subTest(status=status, actor=actor, stamp=stamp):
                self.corrupt(status, actor, stamp)
                prior = self.snapshot()
                with self.assertRaises(ValueError):
                    checked_request_decision_provenance(self.get())
                self.assertEqual(self.snapshot(), prior)

    def test_optin_rejects_record_subclass_and_type_confused_actor(self):
        loaded = self.get()
        class StrangeRecord(type(loaded)):
            pass
        with self.assertRaises(TypeError):
            checked_request_decision_provenance(
                StrangeRecord(**loaded.__dict__)
            )
        self.corrupt("approved", self.op.user_id, datetime.now(timezone.utc).isoformat())
        approved = self.get()
        with self.assertRaises(ValueError):
            checked_request_decision_provenance(
                replace(approved, decided_by=123)
            )

    def test_optin_returns_same_original_record_unmodified(self):
        loaded = self.get()
        before = loaded.__dict__.copy()
        self.assertIs(checked_request_decision_provenance(loaded), loaded)
        self.assertEqual(loaded.__dict__, before)

    def test_foreign_tenant_cannot_select_request(self):
        with self.assertRaises(TenantIsolationError):
            self.store.get_assessment_request(self.foreign, self.record.request_id)

    def test_valid_provenance_does_not_issue_grant_or_run_engagement(self):
        self.store.review_assessment_request(self.op, self.record.request_id, True)
        checked_request_decision_provenance(self.get())
        with sqlite3.connect(self.db) as conn:
            grant_count = conn.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]
            engagement_count = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
        self.assertEqual(grant_count, 0)
        self.assertEqual(engagement_count, 0)


if __name__ == "__main__":
    unittest.main()
