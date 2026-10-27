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
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=allow)
        self.assertIsNotNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "HOLD")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=allow)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_revoke_requires_operator_gate(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=None)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_revoke_unknown_is_denied(self):
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="missing", client_id="client-1", actor="operator-1", operator_gate=allow)

    def test_revoke_different_actor_is_denied(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="different", operator_gate=allow)
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
        receipt = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(receipt["status"], "HOLD")
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(receipt[flag], False)

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
            fresh.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=allow)
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

    def test_issue_does_not_rollback_foreign_open_transaction(self):
        self.db.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('caller-write')")
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(self.db.execute("SELECT value FROM unrelated").fetchone(), ("caller-write",))
        self.db.rollback()

    def test_single_revoke_does_not_rollback_foreign_transaction(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('caller-write')")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=allow)
        self.assertEqual(self.db.execute("SELECT value FROM unrelated").fetchone(), ("caller-write",))
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_bulk_revoke_does_not_rollback_foreign_transaction(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('caller-write')")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1", operator_gate=allow,
            )
        self.assertEqual(self.db.execute("SELECT value FROM unrelated").fetchone(), ("caller-write",))
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_persisted_expiry_widening_is_detected(self):
        self.ledger.issue(**self.items)
        widened = datetime.now(timezone.utc) + timedelta(days=30)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET expires_at=? WHERE run_id=?",
            (widened.isoformat(), "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_persisted_issued_at_backdating_is_detected(self):
        original = self.ledger.issue(**self.items)
        backdated = original.approved_at - timedelta(days=3)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET approved_at=? WHERE run_id=?",
            (backdated.isoformat(), "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_persisted_reversed_window_is_detected(self):
        original = self.ledger.issue(**self.items)
        expiry = original.approved_at - timedelta(seconds=1)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET expires_at=? WHERE run_id=?",
            (expiry.isoformat(), "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_persisted_revocation_before_issue_is_detected(self):
        original = self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1", actor="operator-1", operator_gate=allow)
        impossible = original.approved_at - timedelta(seconds=1)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET revoked_at=? WHERE run_id=?",
            (impossible.isoformat(), "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_persisted_noncanonical_utc_alias_is_rejected(self):
        self.ledger.issue(**self.items)
        self.db.execute(
            """UPDATE lab_stepup_candidates_v1
            SET expires_at=REPLACE(expires_at, '+00:00', 'Z')
            WHERE run_id=?""", ("lab-run-1",),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_persisted_negative_zero_offset_is_rejected(self):
        self.ledger.issue(**self.items)
        self.db.execute(
            """UPDATE lab_stepup_candidates_v1
            SET approved_at=REPLACE(approved_at, '+00:00', '-00:00')
            WHERE run_id=?""", ("lab-run-1",),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_widened_candidate_review_never_promotes_authority(self):
        self.ledger.issue(**self.items)
        future = datetime.now(timezone.utc) + timedelta(days=14)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET expires_at=? WHERE run_id=?",
            (future.isoformat(), "lab-run-1"),
        )
        self.db.commit()
        receipt = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(
            {k: v for k, v in receipt.items() if k != "status"},
            dict.fromkeys(
                ("authorization_verified", "permit_issued", "execution_enabled",
                 "merge_approved", "release_approved"), False,
            ),
        )

    def test_freeze_atomically_revokes_every_tenant_engagement(self):
        self.ledger.issue(**self.items)
        self.ledger.issue(**dict(self.items, run_id="lab-run-2", engagement_id="other-engagement"))
        self.ledger.issue(**dict(self.items, run_id="lab-run-3", client_id="another-client"))
        self.assertEqual(
            self.ledger.freeze_tenant(client_id="client-1", actor="operator-1",
                                      operator_gate=lambda a, action: a == "operator-1" and action == "freeze"),
            2,
        )
        for run in ("lab-run-1", "lab-run-2"):
            item = self.ledger.inspect(run, client_id="client-1")
            self.assertIsNotNone(item.revoked_at)
            receipt = self.ledger.review(run, client_id="client-1")
            self.assertEqual(receipt["status"], "HOLD")
            self.assertTrue(all(x is False for k, x in receipt.items() if k != "status"))
        self.assertEqual(
            self.ledger.review("lab-run-3", client_id="another-client")["status"],
            "REVIEW_ONLY",
        )

    def test_freeze_empty_tenant_prevents_future_first_candidate(self):
        self.assertEqual(
            self.ledger.freeze_tenant(
                client_id="client-1", actor="operator-1",
                operator_gate=lambda *_: True,
            ), 0,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1"))

    def test_freeze_blocks_new_run_even_when_original_revoked(self):
        self.ledger.issue(**self.items)
        self.ledger.freeze_tenant(
            client_id="client-1", actor="operator-1",
            operator_gate=lambda *_: True,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**dict(self.items, run_id="fresh-run"))
        self.assertIsNone(self.ledger.inspect("fresh-run", client_id="client-1"))

    def test_duplicate_freeze_is_durable_and_denied_without_effect(self):
        self.ledger.freeze_tenant(
            client_id="client-1", actor="operator-1",
            operator_gate=lambda *_: True,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.freeze_tenant(
                client_id="client-1", actor="operator-1",
                operator_gate=lambda *_: True,
            )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_freeze_denied_without_operator_approval(self):
        self.ledger.issue(**self.items)
        for operator_gate in (None, lambda *_: False, lambda *_: 1):
            with self.assertRaises(CandidateHeld):
                self.ledger.freeze_tenant(
                    client_id="client-1", actor="operator-1",
                    operator_gate=operator_gate,
                )
        self.assertEqual(
            self.ledger.review("lab-run-1", client_id="client-1")["status"],
            "REVIEW_ONLY",
        )

    def test_freeze_operator_secret_exception_is_redacted(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld) as ctx:
            self.ledger.freeze_tenant(
                client_id="client-1", actor="operator-1",
                operator_gate=Mock(side_effect=RuntimeError("secret-admin-token")),
            )
        self.assertNotIn("secret-admin-token", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_freeze_invalid_selector_does_not_call_operator(self):
        gate = Mock(return_value=True)
        with self.assertRaises(CandidateHeld):
            self.ledger.freeze_tenant(client_id="*",
                                      actor="operator-1", operator_gate=gate)
        # '*' must never be interpreted as a wildcard by the SQL equality
        # selector; reject it entirely before any role verification.
        gate.assert_not_called()

    def test_freeze_preserves_foreign_open_transaction(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('caller-write')")
        with self.assertRaises(CandidateHeld):
            self.ledger.freeze_tenant(
                client_id="client-1", actor="operator-1",
                operator_gate=lambda *_: True,
            )
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT value FROM unrelated").fetchone(),
            ("caller-write",),
        )
        self.db.rollback()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_freeze_persists_after_sqlite_reopen_and_blocks_issue(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tenant-freeze.db"
            first = sqlite3.connect(path)
            LabApprovalCandidateLedger(first).freeze_tenant(
                client_id="client-1", actor="operator-1",
                operator_gate=lambda *_: True,
            )
            first.close()
            second = sqlite3.connect(path)
            reopened = LabApprovalCandidateLedger(second)
            with self.assertRaises(CandidateHeld):
                reopened.issue(**self.items)
            second.close()

    def test_freeze_receipt_holds_even_after_candidate_row_tamper(self):
        self.ledger.issue(**self.items)
        self.ledger.freeze_tenant(
            client_id="client-1", actor="operator-1",
            operator_gate=lambda *_: True,
        )
        # Local writer is untrusted; deliberately wipe the candidate's
        # revocation marker. The independent frozen-tenant row still HOLDs.
        self.db.execute(
            """UPDATE lab_stepup_candidates_v1
            SET revoked_at=NULL, revoked_by=NULL WHERE run_id=?""",
            ("lab-run-1",),
        )
        self.db.commit()
        receipt = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(receipt["status"], "HOLD")
        self.assertTrue(all(value is False for key, value in receipt.items()
                            if key != "status"))

    def test_engagement_freeze_revokes_only_exact_engagement(self):
        self.ledger.issue(**self.items)
        self.ledger.issue(**dict(self.items, run_id="run-same", asset="lab-2"))
        self.ledger.issue(**dict(self.items, run_id="run-other-eng",
                                 engagement_id="engagement-2"))
        self.ledger.issue(**dict(self.items, run_id="run-other-tenant",
                                 client_id="client-2"))
        count = self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda actor, action: action == "freeze",
        )
        self.assertEqual(count, 2)
        for run in ("lab-run-1", "run-same"):
            self.assertEqual(self.ledger.review(run, client_id="client-1")["status"], "HOLD")
            self.assertIsNotNone(self.ledger.inspect(run, client_id="client-1").revoked_at)
        self.assertEqual(self.ledger.review("run-other-eng", client_id="client-1")["status"], "REVIEW_ONLY")
        self.assertEqual(self.ledger.review("run-other-tenant", client_id="client-2")["status"], "REVIEW_ONLY")

    def test_engagement_freeze_prevents_later_run_but_not_other_engagement(self):
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)
        allowed = self.ledger.issue(
            **dict(self.items, engagement_id="engagement-2")
        )
        self.assertEqual(allowed.engagement_id, "engagement-2")

    def test_engagement_freeze_empty_dossier_is_durable(self):
        self.assertEqual(self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        ), 0)
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_engagement_freeze_different_tenant_same_engagement_allowed(self):
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        )
        candidate = self.ledger.issue(**dict(self.items, client_id="client-2"))
        self.assertEqual(candidate.client_id, "client-2")

    def test_engagement_freeze_double_invocation_is_denied_without_undo(self):
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.freeze_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1", operator_gate=lambda *_: True,
            )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**self.items)

    def test_engagement_freeze_requires_exact_operator_true(self):
        for gate in (None, lambda *_: False, lambda *_: 1):
            with self.assertRaises(CandidateHeld):
                self.ledger.freeze_engagement(
                    client_id="client-1", engagement_id="engagement-1",
                    actor="operator-1", operator_gate=gate,
                )
        self.assertIsNotNone(self.ledger.issue(**self.items))

    def test_engagement_freeze_exception_redacts_private_callback(self):
        with self.assertRaises(CandidateHeld) as ctx:
            self.ledger.freeze_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1",
                operator_gate=Mock(side_effect=ValueError("private-approval-details")),
            )
        self.assertNotIn("private-approval-details", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNotNone(self.ledger.issue(**self.items))

    def test_engagement_freeze_rejects_wildcard_before_operator(self):
        for value in ("*", "eng%", "eng?", " eng", "eng\nname"):
            gate = Mock(return_value=True)
            with self.assertRaises(CandidateHeld):
                self.ledger.freeze_engagement(
                    client_id="client-1", engagement_id=value,
                    actor="operator-1", operator_gate=gate,
                )
            gate.assert_not_called()

    def test_engagement_freeze_does_not_rollback_foreign_transaction(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (value TEXT)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('caller')")
        with self.assertRaises(CandidateHeld):
            self.ledger.freeze_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1", operator_gate=lambda *_: True,
            )
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(self.db.execute("SELECT value FROM unrelated").fetchone(), ("caller",))
        self.db.rollback()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_engagement_freeze_persists_across_sqlite_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "engagement-freeze.sqlite"
            db1 = sqlite3.connect(path)
            LabApprovalCandidateLedger(db1).freeze_engagement(
                client_id="client-1", engagement_id="engagement-1",
                actor="operator-1", operator_gate=lambda *_: True,
            )
            db1.close()
            db2 = sqlite3.connect(path)
            ledger2 = LabApprovalCandidateLedger(db2)
            with self.assertRaises(CandidateHeld):
                ledger2.issue(**self.items)
            self.assertEqual(ledger2.review("lab-run-1", client_id="client-1")["status"], "HOLD")
            db2.close()

    def test_engagement_freeze_tampered_candidate_marker_still_holds(self):
        self.ledger.issue(**self.items)
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        )
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET revoked_at=NULL,revoked_by=NULL WHERE run_id=?",
            ("lab-run-1",),
        )
        self.db.commit()
        receipt = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(receipt["status"], "HOLD")
        self.assertTrue(all(value is False for key, value in receipt.items() if key != "status"))

    def test_tenant_freeze_and_engagement_freeze_compose(self):
        self.ledger.issue(**self.items)
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True,
        )
        self.ledger.freeze_tenant(
            client_id="client-1", actor="operator-1",
            operator_gate=lambda *_: True,
        )
        with self.assertRaises(CandidateHeld):
            self.ledger.issue(**dict(self.items, run_id="run-new", engagement_id="engagement-2"))
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_single_run_revocation_cannot_modify_other_tenant(self):
        self.ledger.issue(**self.items)
        foreign = dict(self.items, client_id="client-2", run_id="foreign-run")
        self.ledger.issue(**foreign)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(
                run_id="foreign-run", client_id="client-1",
                actor="operator-1", operator_gate=allow,
            )
        self.assertIsNone(
            self.ledger.inspect("foreign-run", client_id="client-2").revoked_at
        )
        self.assertEqual(self.ledger.review("foreign-run", client_id="client-2")["status"],
                         "REVIEW_ONLY")

    def test_single_run_requires_client_id_keyword(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(TypeError):
            self.ledger.revoke(run_id="lab-run-1", actor="operator-1", operator_gate=allow)
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_single_run_wrong_tenant_does_not_consume_revocation(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(
                run_id="lab-run-1", client_id="other-client",
                actor="operator-1", operator_gate=allow,
            )
        self.ledger.revoke(
            run_id="lab-run-1", client_id="client-1",
            actor="operator-1", operator_gate=allow,
        )
        self.assertEqual(self.ledger.review("lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_single_run_invalid_tenant_denied_before_role_callback(self):
        self.ledger.issue(**self.items)
        for tenant in ("*", "client%", "client?", " client-1", "client\n1"):
            gate = Mock(return_value=True)
            with self.assertRaises(CandidateHeld):
                self.ledger.revoke(
                    run_id="lab-run-1", client_id=tenant,
                    actor="operator-1", operator_gate=gate,
                )
            gate.assert_not_called()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)

    def test_single_run_scoped_revoke_persists_across_new_connection(self):
        with tempfile.TemporaryDirectory() as folder:
            dbpath = Path(folder) / "scoped-revoke.sqlite"
            first = sqlite3.connect(dbpath)
            ledger1 = LabApprovalCandidateLedger(first)
            ledger1.issue(**self.items)
            ledger1.revoke(
                run_id="lab-run-1", client_id="client-1",
                actor="operator-1", operator_gate=allow,
            )
            first.close()
            second = sqlite3.connect(dbpath)
            ledger2 = LabApprovalCandidateLedger(second)
            self.assertEqual(ledger2.review("lab-run-1", client_id="client-1")["status"], "HOLD")
            second.close()

    def test_single_run_wrong_tenant_does_not_rollback_other_transaction(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (note TEXT)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('preserve')")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(
                run_id="lab-run-1", client_id="other-client",
                actor="operator-1", operator_gate=allow,
            )
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT note FROM unrelated").fetchone(), ("preserve",)
        )
        self.db.rollback()
        self.assertIsNone(self.ledger.inspect("lab-run-1", client_id="client-1").revoked_at)


    def test_single_revoke_writes_exact_tenant_tombstone(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        row = self.db.execute(
            """SELECT revoked_at,revoked_by FROM lab_stepup_candidate_revocations_v1
               WHERE run_id=? AND client_id=?""",
            ("lab-run-1", "client-1"),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "operator-1")
        self.assertEqual(row[0], self.ledger.inspect(
            "lab-run-1", client_id="client-1").revoked_at.isoformat())

    def test_cleared_revocation_timestamp_does_not_resurrect_candidate(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            """UPDATE lab_stepup_candidates_v1
            SET revoked_at=NULL,revoked_by=NULL WHERE run_id=?""",
            ("lab-run-1",),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")
        result = self.ledger.review("lab-run-1", client_id="client-1")
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(all(val is False for key, val in result.items()
                            if key != "status"))

    def test_cleared_only_revoked_at_is_corrupt(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET revoked_at=NULL WHERE run_id=?",
            ("lab-run-1",),
        )
        self.db.commit()
        self.assertEqual(self.ledger.review(
            "lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_cleared_only_revoked_by_is_corrupt(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET revoked_by=NULL WHERE run_id=?",
            ("lab-run-1",),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")
        self.assertEqual(self.ledger.review(
            "lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_tombstone_attribution_mismatch_is_corrupt(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET revoked_by=? WHERE run_id=?",
            ("other-actor", "lab-run-1"),
        )
        self.db.commit()
        with self.assertRaises(CandidateHeld):
            self.ledger.inspect("lab-run-1", client_id="client-1")

    def test_tombstone_timestamp_mismatch_is_corrupt(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            """UPDATE lab_stepup_candidate_revocations_v1
               SET revoked_at=? WHERE run_id=?""",
            ("2000-01-01T00:00:00+00:00", "lab-run-1"),
        )
        self.db.commit()
        self.assertEqual(self.ledger.review(
            "lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_tombstone_owner_mismatch_is_corrupt(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        self.db.execute(
            """UPDATE lab_stepup_candidate_revocations_v1
               SET revoked_by=? WHERE run_id=?""",
            ("forged-actor", "lab-run-1"),
        )
        self.db.commit()
        self.assertEqual(self.ledger.review(
            "lab-run-1", client_id="client-1")["status"], "HOLD")

    def test_bulk_engagement_revocation_marks_exact_runs_only(self):
        self.ledger.issue(**self.items)
        self.ledger.issue(**dict(self.items, run_id="run-two"))
        self.ledger.issue(**dict(self.items, run_id="other-eng",
                                 engagement_id="engagement-2"))
        self.assertEqual(self.ledger.revoke_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=allow), 2)
        found = self.db.execute(
            "SELECT run_id FROM lab_stepup_candidate_revocations_v1 ORDER BY run_id"
        ).fetchall()
        self.assertEqual(found, [("lab-run-1",), ("run-two",)])
        self.assertEqual(self.ledger.review(
            "other-eng", client_id="client-1")["status"], "REVIEW_ONLY")

    def test_freeze_tenant_writes_exact_client_tombstones(self):
        self.ledger.issue(**self.items)
        self.ledger.issue(**dict(self.items, run_id="other-tenant",
                                 client_id="client-2"))
        self.assertEqual(self.ledger.freeze_tenant(
            client_id="client-1", actor="operator-1",
            operator_gate=lambda *_: True), 1)
        self.assertEqual(self.db.execute(
            "SELECT run_id FROM lab_stepup_candidate_revocations_v1"
        ).fetchall(), [("lab-run-1",)])
        self.assertEqual(self.ledger.review(
            "other-tenant", client_id="client-2")["status"], "REVIEW_ONLY")

    def test_freeze_engagement_writes_exact_engagement_tombstones(self):
        self.ledger.issue(**self.items)
        self.ledger.issue(**dict(self.items, run_id="other-eng",
                                 engagement_id="engagement-2"))
        self.assertEqual(self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="engagement-1",
            actor="operator-1", operator_gate=lambda *_: True), 1)
        self.assertEqual(self.db.execute(
            "SELECT run_id FROM lab_stepup_candidate_revocations_v1"
        ).fetchall(), [("lab-run-1",)])
        self.assertEqual(self.ledger.review(
            "other-eng", client_id="client-1")["status"], "REVIEW_ONLY")

    def test_duplicate_revoke_keeps_single_tombstone(self):
        self.ledger.issue(**self.items)
        self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                               actor="operator-1", operator_gate=allow)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM lab_stepup_candidate_revocations_v1"
        ).fetchone()[0], 1)

    def test_wrong_tenant_cannot_write_any_tombstone(self):
        self.ledger.issue(**self.items)
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-2",
                               actor="operator-1", operator_gate=allow)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM lab_stepup_candidate_revocations_v1"
        ).fetchone()[0], 0)
        self.assertEqual(self.ledger.review(
            "lab-run-1", client_id="client-1")["status"], "REVIEW_ONLY")

    def test_tombstone_survives_reopening_and_marker_damage(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "revoked.db"
            db1 = sqlite3.connect(filename)
            ledger1 = LabApprovalCandidateLedger(db1)
            ledger1.issue(**self.items)
            ledger1.revoke(run_id="lab-run-1", client_id="client-1",
                           actor="operator-1", operator_gate=allow)
            db1.close()
            db2 = sqlite3.connect(filename)
            db2.execute(
                """UPDATE lab_stepup_candidates_v1
                SET revoked_at=NULL,revoked_by=NULL WHERE run_id='lab-run-1'"""
            )
            db2.commit()
            self.assertEqual(LabApprovalCandidateLedger(db2).review(
                "lab-run-1", client_id="client-1")["status"], "HOLD")
            db2.close()

    def test_failed_revocation_keeps_outer_transaction_owned_by_caller(self):
        self.ledger.issue(**self.items)
        self.db.execute("CREATE TABLE unrelated (detail TEXT)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO unrelated VALUES ('preserve')")
        with self.assertRaises(CandidateHeld):
            self.ledger.revoke(run_id="lab-run-1", client_id="client-1",
                               actor="operator-1", operator_gate=allow)
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(self.db.execute(
            "SELECT detail FROM unrelated").fetchone(), ("preserve",))
        self.db.rollback()
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM lab_stepup_candidate_revocations_v1"
        ).fetchone()[0], 0)



if __name__ == "__main__":
    unittest.main()
