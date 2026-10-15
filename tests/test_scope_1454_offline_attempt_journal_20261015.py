"""No-authority acceptance for the isolated #1454 attempt journal reference."""
from __future__ import annotations

import dataclasses
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scope_1454_offline_attempt_journal import (
    OfflineAttemptJournal, ReviewReceipt, SyntheticAttempt,
)


def fixture(**changes) -> SyntheticAttempt:
    fields = dict(
        attempt_id="fixture-attempt-a",
        run_id="fixture-run-a",
        client_id="fixture-client-a",
        engagement_id="fixture-engagement-a",
        grant_id="fixture-grant-a",
        tool_id="fixture-tool-a",
        capability_id="fixture-capability-a",
        asset="fixture-asset.invalid",
        risk=2,
    )
    fields.update(changes)
    return SyntheticAttempt(**fields)


class OfflineAttemptJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-1454-reference-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "only-fictional-attempts.db")
        self.con = sqlite3.connect(self.path, timeout=2)
        self.addCleanup(self.con.close)
        self.journal = OfflineAttemptJournal(self.con)
        self.attempt = fixture()

    def assert_non_authorizing(self, receipt: ReviewReceipt, status: str) -> None:
        self.assertEqual(type(receipt), ReviewReceipt)
        self.assertEqual(receipt.status, status)
        report = receipt.as_dict()
        self.assertEqual(set(report), {
            "status", "reason", "authorization_allowed", "permit_allowed",
            "dispatch_allowed", "merge_allowed", "deploy_allowed",
            "release_allowed",
        })
        self.assertEqual(report["status"], status)
        for key in (
            "authorization_allowed", "permit_allowed", "dispatch_allowed",
            "merge_allowed", "deploy_allowed", "release_allowed",
        ):
            self.assertIs(report[key], False)
        rendered = str(report)
        self.assertNotIn("fixture-client", rendered)
        self.assertNotIn("fixture-asset", rendered)
        self.assertNotIn("fixture-run", rendered)
        self.assertNotIn("fixture-grant", rendered)
        with self.assertRaises(TypeError):
            bool(receipt)

    def count(self) -> int:
        return self.con.execute(
            "SELECT count(*) FROM offline_scope_1454_attempts"
        ).fetchone()[0]

    def test_constructor_rejects_forged_authorization_receipts(self):
        for status, reason, flags in (
            ("APPROVED", "not_an_execution_authorization", {}),
            ("REVIEW_ONLY", "approved", {}),
            ("HOLD", "manual_review_required", {"dispatch_allowed": True}),
            ("REVIEW_ONLY", "not_an_execution_authorization",
             {"release_allowed": 1}),
        ):
            with self.subTest(status=status, flags=flags):
                with self.assertRaises(ValueError):
                    ReviewReceipt(status, reason, **flags)

    def test_mutated_or_extra_receipt_fields_redact_to_hold(self):
        receipt = self.journal.reserve(self.attempt)
        self.assert_non_authorizing(receipt, "REVIEW_ONLY")
        object.__setattr__(receipt, "status", "APPROVED")
        self.assertEqual(receipt.as_dict()["status"], "HOLD")
        object.__setattr__(receipt, "status", "REVIEW_ONLY")
        object.__setattr__(receipt, "dispatch_allowed", True)
        self.assertEqual(receipt.as_dict()["status"], "HOLD")
        object.__setattr__(receipt, "dispatch_allowed", False)
        object.__setattr__(receipt, "private_claim", "fixture-client-secret")
        rendered = str(receipt.as_dict())
        self.assertNotIn("fixture-client", rendered)
        self.assertEqual(receipt.as_dict()["status"], "HOLD")

    def test_missing_receipt_field_and_subclass_are_hold_only(self):
        receipt = self.journal.reserve(self.attempt)
        object.__delattr__(receipt, "reason")
        self.assert_non_authorizing(
            ReviewReceipt("HOLD", "manual_review_required"), "HOLD")
        self.assertEqual(receipt.as_dict()["status"], "HOLD")
        class ForgedReceipt(ReviewReceipt):
            pass
        with self.assertRaises(ValueError):
            ForgedReceipt("REVIEW_ONLY", "not_an_execution_authorization")

    def test_initially_empty_and_no_authority(self):
        self.assertEqual(self.count(), 0)
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")

    def test_reservation_is_durable_before_any_mock_handler(self):
        calls: list[str] = []
        receipt = self.journal.reserve(self.attempt)
        self.assert_non_authorizing(receipt, "REVIEW_ONLY")
        self.assertEqual(calls, [])
        self.assertEqual(self.count(), 1)
        with closing(sqlite3.connect(self.path)) as second:
            row = second.execute(
                "SELECT phase FROM offline_scope_1454_attempts WHERE attempt_id=?",
                (self.attempt.attempt_id,)
            ).fetchone()
            self.assertEqual(row, ("reserved",))
        # Only test code calls this inert in-memory callback after reviewing
        # the durable reservation; the reference has no dispatch method.
        calls.append("inert-test-only")
        self.assertEqual(calls, ["inert-test-only"])

    def test_exact_duplicate_and_mismatched_binding_are_both_hold(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        other = dataclasses.replace(self.attempt, client_id="fixture-other-client")
        self.assert_non_authorizing(self.journal.reserve(other), "HOLD")
        self.assertEqual(self.journal.review_phase(other)[0], "unknown")
        self.assertEqual(self.count(), 1)

    def test_failure_after_callback_is_nonreplayable(self):
        self.journal.reserve(self.attempt)
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "REVIEW_ONLY")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "uncertain")
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assert_non_authorizing(
            self.journal.mark_recorded(self.attempt, "a" * 64), "HOLD")
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertEqual(self.count(), 1)

    def test_recorded_evidence_is_terminal_and_non_replayable(self):
        self.journal.reserve(self.attempt)
        good_digest = hashlib.sha256(b"fictional observation").hexdigest()
        self.assert_non_authorizing(
            self.journal.mark_recorded(self.attempt, good_digest), "REVIEW_ONLY")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "recorded")
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertEqual(
            self.con.execute(
                "SELECT evidence_digest FROM offline_scope_1454_attempts"
            ).fetchone()[0],
            good_digest,
        )

    def test_transitions_without_reservation_refuse(self):
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assert_non_authorizing(
            self.journal.mark_recorded(self.attempt, "c" * 64), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_exact_digest_shapes_only(self):
        self.journal.reserve(self.attempt)
        for digest in (
            "", "a" * 63, "a" * 65, "A" * 64, True, 42, None,
            float("nan"), "a" * 63 + "\n",
        ):
            with self.subTest(digest=str(type(digest))):
                self.assert_non_authorizing(
                    self.journal.mark_recorded(self.attempt, digest), "HOLD")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")

    def test_all_authorization_identity_components_sealed(self):
        self.journal.reserve(self.attempt)
        for field in (
            "run_id", "client_id", "engagement_id", "grant_id", "tool_id",
            "capability_id", "asset", "risk",
        ):
            value = getattr(self.attempt, field)
            other = dataclasses.replace(
                self.attempt, **{field: 3 if field == "risk" else
                                ("fixture-other.invalid" if field == "asset" else
                                 "fixture-other")})
            with self.subTest(field=field):
                self.assertNotEqual(value, getattr(other, field))
                self.assert_non_authorizing(self.journal.mark_uncertain(other), "HOLD")
                self.assertEqual(self.journal.review_phase(other)[0], "unknown")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")

    def test_strict_primitive_and_synthetic_scope_intake(self):
        class Lookalike(str):
            pass
        invalid = [
            dict(attempt_id="real-id"), dict(run_id="other-tenant"),
            dict(asset="real.example.org"), dict(asset="fixture-A.invalid"),
            dict(client_id=Lookalike("fixture-client-a")),
            dict(tool_id="fixture-tool-a\u202e"),
            dict(capability_id="fixture-capability-a\n"),
            dict(grant_id="fixture-"),
            dict(risk=True), dict(risk=5), dict(risk=-1),
            dict(risk=2.0), dict(risk=float("nan")),
            dict(risk="2"), dict(risk=None),
        ]
        for i, override in enumerate(invalid):
            with self.subTest(i=i):
                self.assert_non_authorizing(
                    self.journal.reserve(fixture(**override)), "HOLD")
        self.assert_non_authorizing(self.journal.reserve(object()), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_dirty_customer_schema_is_rejected_without_changes(self):
        with closing(sqlite3.connect(str(Path(self.temp.name) / "not_a_fixture.db"))) as con:
            con.execute("CREATE TABLE customer_records (sensitive TEXT)")
            con.execute("INSERT INTO customer_records VALUES ('do-not-touch')")
            con.commit()  # check schema rejection, not merely active-transaction rejection
            with self.assertRaises(ValueError):
                OfflineAttemptJournal(con)
            self.assertEqual(con.execute(
                "SELECT sensitive FROM customer_records"
            ).fetchone()[0], "do-not-touch")
            self.assertIsNone(con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name='offline_scope_1454_attempts'"
            ).fetchone())

    def test_real_sqlite_preinsert_failure_atomic_hold(self):
        self.con.execute("""
            CREATE TRIGGER refuse_offline_reservation
            BEFORE INSERT ON offline_scope_1454_attempts
            BEGIN SELECT RAISE(ABORT, 'fixture_only_db_failure'); END;
        """)
        self.con.commit()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_real_sqlite_preupdate_failure_preserves_reserved(self):
        self.journal.reserve(self.attempt)
        self.con.execute("""
            CREATE TRIGGER refuse_offline_update
            BEFORE UPDATE ON offline_scope_1454_attempts
            BEGIN SELECT RAISE(ABORT, 'fixture_only_db_failure'); END;
        """)
        self.con.commit()
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")
        self.assertEqual(self.count(), 1)

    def test_wrong_binding_cannot_finish_or_borrow_state(self):
        self.journal.reserve(self.attempt)
        other = dataclasses.replace(
            self.attempt, attempt_id="fixture-other-attempt")
        self.assert_non_authorizing(
            self.journal.mark_recorded(other, "d" * 64), "HOLD")
        self.assertEqual(self.count(), 1)

    def test_new_connection_still_denies_replay_after_crash_simulation(self):
        self.journal.reserve(self.attempt)
        with closing(sqlite3.connect(self.path, timeout=2)) as con:
            replay = OfflineAttemptJournal(con)
            self.assert_non_authorizing(replay.reserve(self.attempt), "HOLD")
            self.assertEqual(replay.review_phase(self.attempt)[0], "reserved")
            self.assert_non_authorizing(replay.mark_uncertain(self.attempt), "REVIEW_ONLY")
        with closing(sqlite3.connect(self.path, timeout=2)) as con:
            again = OfflineAttemptJournal(con)
            self.assertEqual(again.review_phase(self.attempt)[0], "uncertain")
            self.assert_non_authorizing(again.reserve(self.attempt), "HOLD")

    def test_concurrent_racers_cannot_reserve_same_attempt_twice(self):
        barrier = threading.Barrier(2)
        results: list[str] = []
        errors: list[str] = []
        def contender() -> None:
            try:
                with closing(sqlite3.connect(self.path, timeout=5)) as con:
                    candidate = OfflineAttemptJournal(con)
                    barrier.wait(timeout=5)
                    results.append(candidate.reserve(self.attempt).status)
            except (RuntimeError, sqlite3.Error, threading.BrokenBarrierError):
                errors.append("concurrent_fixture_error")
        workers = [threading.Thread(target=contender) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=8)
        self.assertFalse(any(w.is_alive() for w in workers))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), ["HOLD", "REVIEW_ONLY"])
        self.assertEqual(self.count(), 1)


if __name__ == "__main__":
    unittest.main()
