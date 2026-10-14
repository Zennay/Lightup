"""Genuine SQLite-only safety checks for the opt-in #1173 candidate ledger."""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from lightup.lab_approval_candidate_ledger import (
    CandidateHeld, LabApprovalCandidateLedger,
)


def allow(actor, action):
    return actor == "operator-1" and action in {"issue", "revoke"}


class CandidateLedgerTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.ledger = LabApprovalCandidateLedger(self.db)
        self.items = dict(
            run_id="lab-run-1", client_id="client-1",
            engagement_id="engagement-1", asset="isolated-lab-1",
            capability_id="lab-control", tool_id="lab-test",
            actor="operator-1", operator_gate=allow,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    def tearDown(self):
        self.db.close()

    def test_issue_is_durable_and_non_authorizing(self):
        approval = self.ledger.issue(**self.items)
        read = self.ledger.inspect("lab-run-1", client_id="client-1")
        self.assertEqual(read, approval)
        self.assertIsNone(read.revoked_at)
        result = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(result["status"], "REVIEW_ONLY")
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(result[flag], False)

    def test_missing_candidate_holds(self):
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1"))
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_issue_without_operator_gate_is_rejected_without_row(self):
        self.items["operator_gate"] = None
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1"))

    def test_operator_denial_has_no_write(self):
        self.items["operator_gate"] = lambda *_: False
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1"))

    def test_truthy_non_boolean_operator_proof_is_rejected(self):
        self.items["operator_gate"] = lambda *_: 1
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_operator_exception_detail_is_redacted(self):
        self.items["operator_gate"] = Mock(side_effect=RuntimeError("secret-credential"))
        with self.assertRaises(CandidateHeld) as ctx:
            self.ledger.issue(**self.items)
        self.assertNotIn("secret-credential", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)

    def test_malformed_envelope_never_invokes_gate(self):
        gate = Mock(return_value=True)
        self.items.update(asset="bad\nasset", operator_gate=gate)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        gate.assert_not_called()

    def test_duplicate_run_cannot_reissue(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM lab_stepup_candidates_v1"
        ).fetchone()[0], 1)

    def test_different_run_can_be_issued(self):
        self.ledger.issue(**self.items)
        self.items["run_id"] = "lab-run-2"
        self.ledger.issue(**self.items)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM lab_stepup_candidates_v1"
        ).fetchone()[0], 2)

    def test_revocation_is_durable_and_cannot_be_reversed(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", actor="operator-1", operator_gate=allow)
        self.assertIsNotNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "HOLD")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", actor="operator-1", operator_gate=allow)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_revoke_requires_operator_gate(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", actor="operator-1", operator_gate=None)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_revoke_unknown_is_denied(self):
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="missing", actor="operator-1", operator_gate=allow)

    def test_revoke_different_actor_is_denied(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", actor="different", operator_gate=allow)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_naive_time_rejected_before_operator(self):
        gate = Mock(return_value=True)
        self.items.update(expires_at=datetime.utcnow(), operator_gate=gate)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        gate.assert_not_called()

    def test_subclassed_time_rejected(self):
        class HostileDate(datetime):
            pass
        self.items["expires_at"] = HostileDate.now(timezone.utc) + timedelta(hours=1)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_non_utc_offset_rejected(self):
        self.items["expires_at"] = datetime.now(timezone(timedelta(hours=2))) + timedelta(hours=1)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_window_over_24h_rejected(self):
        self.items["expires_at"] = datetime.now(timezone.utc) + timedelta(hours=25)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_expired_window_rejected(self):
        self.items["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_tainted_stored_timestamp_holds(self):
        self.ledger.issue(**self.items)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET expires_at='broken' WHERE run_id='lab-run-1'"
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.review("lab-run-1", client_id="client-1")

    def test_corrupt_identity_holds(self):
        self.ledger.issue(**self.items)
        # Corrupt a non-tenant field while keeping tenant identity intact.
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET asset=? WHERE run_id=?",
            ("other\nasset", "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_file_backed_sqlite_survives_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "candidate.db"
            first = sqlite3.connect(path)
            ledger = LabApprovalCandidateLedger(first)
            ledger.issue(**self.items)
            first.close()
            second = sqlite3.connect(path)
            fresh = LabApprovalCandidateLedger(second)
            self.assertEqual(fresh.review("lab-run-1", client_id="client-1")["status"], "REVIEW_ONLY")
            fresh.revoke(run_id="lab-run-1", actor="operator-1", operator_gate=allow)
            second.close()
            third = sqlite3.connect(path)
            self.assertEqual(LabApprovalCandidateLedger(third).review(
                "lab-run-1", client_id="client-1"
            )["status"], "HOLD")
            third.close()

    def test_foreign_tenant_lookup_never_returns_candidate(self):
        self.ledger.issue(**self.items)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="other-client"))
        self.assertEqual(
            self.ledger.review("lab-run-1", client_id="other-client")["status"],
            "HOLD",
        )

    def test_invalid_tenant_lookup_fails_closed(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client\nforged")

    def test_engagement_revocation_is_tenant_scoped_and_atomic(self):
        self.ledger.issue(**self.items)
        same = dict(self.items, run_id="lab-run-2")
        self.ledger.issue(**same)
        foreign = dict(self.items, run_id="lab-run-3", client_id="other-client")
        self.ledger.issue(**foreign)
        unrelated = dict(self.items, run_id="lab-run-4", engagement_id="other-engagement")
        self.ledger.issue(**unrelated)
        count = self.ledger.revoke_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=allow,
        )
        self.assertEqual(count, 2)
        for run in ("lab-run-1", "lab-run-2"):
            self.assertEqual(self.ledger.review(run, client_id="client-1")["status"], "HOLD")
        self.assertEqual(
            self.ledger.review("lab-run-3", client_id="other-client")["status"],
            "REVIEW_ONLY",
        )
        self.assertEqual(self.ledger.review("lab-run-4", client_id="client-1")["status"], "REVIEW_ONLY")

    def test_empty_engagement_revocation_is_denied(self):
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1", operator_gate=allow,
            )

    def test_engagement_revocation_requires_operator_role(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="untrusted", operator_gate=allow,
            )
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
