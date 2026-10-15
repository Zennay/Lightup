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

    def test_preexisting_same_name_table_with_no_primary_key_refused(self):
        path = str(Path(self.temp.name) / "forged_reference_schema.db")
        with closing(sqlite3.connect(path)) as con:
            con.execute(
                "CREATE TABLE offline_scope_1454_attempts ("
                "attempt_id TEXT, sealed_binding TEXT, phase TEXT, evidence_digest TEXT)"
            )
            con.commit()
            with self.assertRaises(ValueError):
                OfflineAttemptJournal(con)
            self.assertEqual(con.execute(
                "PRAGMA table_info(offline_scope_1454_attempts)"
            ).fetchall()[0][5], 0)

    def test_preexisting_trigger_must_not_promote_spoofed_reservation(self):
        path = str(Path(self.temp.name) / "triggered_reference.db")
        with closing(sqlite3.connect(path)) as con:
            OfflineAttemptJournal(con)
            con.execute("""
                CREATE TRIGGER ignore_attempt BEFORE INSERT ON
                    offline_scope_1454_attempts
                BEGIN SELECT RAISE(IGNORE); END
            """)
            con.commit()
            with self.assertRaises(ValueError):
                OfflineAttemptJournal(con)

    def test_temp_table_shadowing_reference_is_refused(self):
        with closing(sqlite3.connect(":memory:")) as con:
            OfflineAttemptJournal(con)
            con.execute(
                "CREATE TEMP TABLE offline_scope_1454_attempts ("
                "attempt_id TEXT, sealed_binding TEXT, phase TEXT, evidence_digest TEXT)"
            )
            with self.assertRaises(ValueError):
                OfflineAttemptJournal(con)

    def test_attached_database_cannot_influence_synthetic_journal(self):
        with closing(sqlite3.connect(":memory:")) as con:
            OfflineAttemptJournal(con)
            con.execute("ATTACH DATABASE ':memory:' AS shadow_fixture")
            with self.assertRaises(ValueError):
                OfflineAttemptJournal(con)

    def test_closed_connection_reservation_is_generic_hold(self):
        self.con.close()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "unknown")

    def test_closed_connection_transition_is_generic_hold(self):
        self.journal.reserve(self.attempt)
        self.con.close()
        self.assert_non_authorizing(
            self.journal.mark_uncertain(self.attempt), "HOLD")
        with closing(sqlite3.connect(self.path)) as con:
            recovered = OfflineAttemptJournal(con)
            self.assertEqual(recovered.review_phase(self.attempt)[0], "reserved")
            self.assert_non_authorizing(recovered.reserve(self.attempt), "HOLD")

    def test_existing_caller_transaction_survives_denied_reserve(self):
        self.con.execute("BEGIN IMMEDIATE")
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertTrue(self.con.in_transaction)
        self.con.rollback()
        self.assertEqual(self.count(), 0)

    def test_existing_caller_transaction_survives_denied_transition(self):
        self.journal.reserve(self.attempt)
        self.con.execute("BEGIN IMMEDIATE")
        self.assert_non_authorizing(
            self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertTrue(self.con.in_transaction)
        self.con.rollback()
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")

    def test_same_action_new_attempt_id_is_replay_not_new_authority(self):
        self.assert_non_authorizing(
            self.journal.reserve(self.attempt), "REVIEW_ONLY")
        renamed = dataclasses.replace(
            self.attempt, attempt_id="fixture-same-action-different-id")
        self.assert_non_authorizing(self.journal.reserve(renamed), "HOLD")
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.journal.review_phase(renamed)[0], "unknown")

    def test_new_run_id_creates_independent_synthetic_attempt(self):
        self.journal.reserve(self.attempt)
        next_run = dataclasses.replace(
            self.attempt, attempt_id="fixture-second-attempt", run_id="fixture-run-b")
        self.assert_non_authorizing(self.journal.reserve(next_run), "REVIEW_ONLY")
        self.assertEqual(self.count(), 2)
        self.assertIs(self.journal.review_backlog().as_dict()["dispatch_allowed"], False)

    def test_action_binding_corruption_cannot_finish_or_claim_review(self):
        self.journal.reserve(self.attempt)
        self.con.execute(
            "UPDATE offline_scope_1454_attempts SET operation_fingerprint=?",
            ("f" * 64,),
        )
        self.con.commit()
        self.assert_non_authorizing(
            self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "unknown")
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")

    def test_backlog_reports_only_capped_phase_counts_without_identities(self):
        from scope_1454_offline_attempt_journal import OfflineBacklogReview
        a = self.attempt
        b = fixture(attempt_id="fixture-attempt-b", run_id="fixture-run-b")
        c = fixture(attempt_id="fixture-attempt-c", run_id="fixture-run-c")
        self.journal.reserve(a)
        self.journal.reserve(b)
        self.journal.reserve(c)
        self.journal.mark_uncertain(b)
        self.journal.mark_recorded(c, hashlib.sha256(b"fixture").hexdigest())
        backlog = self.journal.review_backlog()
        self.assertIs(type(backlog), OfflineBacklogReview)
        self.assertEqual(backlog.as_dict()["status"], "REVIEW_ONLY")
        self.assertEqual((
            backlog.as_dict()["reserved_count"],
            backlog.as_dict()["uncertain_count"],
            backlog.as_dict()["recorded_count"],
            backlog.as_dict()["requires_manual_reconciliation"]
        ), (1, 1, 1, 2))
        serialized = str(backlog.as_dict())
        for secret in ("fixture-attempt", "fixture-client", "fixture-asset",
                       "fixture-grant", "fixture-tool", "fixture-run"):
            self.assertNotIn(secret, serialized)
        for field in (
            "authorization_allowed", "permit_allowed", "dispatch_allowed",
            "merge_allowed", "deploy_allowed", "release_allowed",
        ):
            self.assertIs(backlog.as_dict()[field], False)
        with self.assertRaises(TypeError):
            bool(backlog)

    def test_empty_backlog_is_review_only_but_never_permission(self):
        backlog = self.journal.review_backlog()
        projection = backlog.as_dict()
        self.assertEqual(projection["status"], "REVIEW_ONLY")
        self.assertEqual(projection["requires_manual_reconciliation"], 0)
        self.assertIs(projection["dispatch_allowed"], False)

    def test_corrupt_backlog_evidence_row_fails_closed(self):
        self.journal.reserve(self.attempt)
        self.con.execute(
            "UPDATE offline_scope_1454_attempts "
            "SET phase='recorded', evidence_digest='broken'"
        )
        self.con.commit()
        backlog = self.journal.review_backlog().as_dict()
        self.assertEqual(backlog["status"], "HOLD")
        self.assertEqual(backlog["recorded_count"], 0)
        self.assertIs(backlog["authorization_allowed"], False)

    def test_corrupt_backlog_binding_fails_closed(self):
        self.journal.reserve(self.attempt)
        self.con.execute(
            "UPDATE offline_scope_1454_attempts SET sealed_binding='bad'"
        )
        self.con.commit()
        self.assertEqual(self.journal.review_backlog().as_dict()["status"], "HOLD")

    def test_backlog_schema_poisoning_and_open_transaction_are_hold(self):
        self.journal.reserve(self.attempt)
        self.con.execute("BEGIN IMMEDIATE")
        projection = self.journal.review_backlog().as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["reserved_count"], 0)
        self.assertTrue(self.con.in_transaction)
        self.con.rollback()
        self.con.execute("CREATE TABLE late_customer (secret TEXT)")
        self.con.commit()
        projection = self.journal.review_backlog().as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["reserved_count"], 0)

    def test_backlog_cap_above_256_is_generic_hold_without_ids(self):
        binding = "a" * 64
        for index in range(257):
            self.con.execute(
                "INSERT INTO offline_scope_1454_attempts "
                "(attempt_id,sealed_binding,operation_fingerprint,phase,evidence_digest) "
                "VALUES(?,?,?,'reserved',NULL)",
                (f"fixture-batch-{index}", binding, f"{index:064x}")
            )
        self.con.commit()
        projection = self.journal.review_backlog().as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["reserved_count"], 0)
        self.assertIs(projection["release_allowed"], False)

    def test_backlog_dead_connection_is_generic_hold(self):
        self.con.close()
        projection = self.journal.review_backlog().as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["uncertain_count"], 0)

    def test_backlog_forged_count_and_receipt_fail_closed(self):
        from scope_1454_offline_attempt_journal import OfflineBacklogReview
        with self.assertRaises(ValueError):
            OfflineBacklogReview(ReviewReceipt("HOLD", "manual_review_required"), 1, 0, 0)
        with self.assertRaises(ValueError):
            OfflineBacklogReview(ReviewReceipt("REVIEW_ONLY",
                                              "not_an_execution_authorization"), True, 0, 0)
        backlog = self.journal.review_backlog()
        object.__setattr__(backlog.receipt, "status", "APPROVED")
        projection = backlog.as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["requires_manual_reconciliation"], 0)

    def test_backlog_mutated_counters_are_privacy_redacted(self):
        self.journal.reserve(self.attempt)
        backlog = self.journal.review_backlog()
        object.__setattr__(backlog, "reserved_count", "fixture-client-sensitive")
        projection = backlog.as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertEqual(projection["reserved_count"], 0)
        self.assertNotIn("fixture-client-sensitive", str(projection))
        self.assertIs(projection["dispatch_allowed"], False)

    def test_backlog_mutated_extra_claims_are_privacy_redacted(self):
        backlog = self.journal.review_backlog()
        object.__setattr__(backlog, "private_payload", "fixture-secret-do-not-expose")
        projection = backlog.as_dict()
        self.assertEqual(projection["status"], "HOLD")
        self.assertNotIn("fixture-secret", str(projection))
        self.assertIs(projection["release_allowed"], False)

    def test_corrupted_reserved_digest_must_not_finish_attempt(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        self.con.execute(
            "UPDATE offline_scope_1454_attempts SET evidence_digest=?",
            ("a" * 64,),
        )
        self.con.commit()
        self.assert_non_authorizing(
            self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assert_non_authorizing(
            self.journal.mark_recorded(self.attempt, "b" * 64), "HOLD")
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")

    def test_recorded_without_exact_digest_must_not_be_reviewed(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        for bad_digest in (None, "", "a" * 63, "A" * 64, "a" * 65):
            with self.subTest(digest=repr(bad_digest)):
                self.con.execute(
                    "UPDATE offline_scope_1454_attempts "
                    "SET phase='recorded', evidence_digest=?",
                    (bad_digest,),
                )
                self.con.commit()
                phase, receipt = self.journal.review_phase(self.attempt)
                self.assertEqual(phase, "unknown")
                self.assert_non_authorizing(receipt, "HOLD")

    def test_uncertain_phase_with_digest_must_not_be_reviewed(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        self.con.execute(
            "UPDATE offline_scope_1454_attempts "
            "SET phase='uncertain', evidence_digest=?",
            ("c" * 64,),
        )
        self.con.commit()
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")

    def test_valid_recorded_sha256_remains_review_only(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        exact = hashlib.sha256(b"fictional-evidence").hexdigest()
        self.assert_non_authorizing(
            self.journal.mark_recorded(self.attempt, exact), "REVIEW_ONLY")
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "recorded")
        self.assert_non_authorizing(receipt, "REVIEW_ONLY")

    def test_late_benign_trigger_cannot_pass_offline_schema_check(self):
        self.con.execute("""
            CREATE TRIGGER late_benign_trigger AFTER INSERT
            ON offline_scope_1454_attempts
            BEGIN SELECT 1; END
        """)
        self.con.commit()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_late_customer_table_rejects_unrelated_fixture_mutation(self):
        self.con.execute("CREATE TABLE late_customer_record (private TEXT)")
        self.con.execute("INSERT INTO late_customer_record VALUES ('fixture-secret')")
        self.con.commit()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.con.execute(
            "SELECT private FROM late_customer_record"
        ).fetchone()[0], "fixture-secret")

    def test_late_attached_db_rejects_reservation(self):
        self.con.execute("ATTACH DATABASE ':memory:' AS late_connection")
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_late_temp_shadow_rejects_reservation(self):
        self.con.execute(
            "CREATE TEMP TABLE offline_scope_1454_attempts "
            "(attempt_id TEXT, sealed_binding TEXT, phase TEXT)"
        )
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_late_schema_poisoning_prevents_state_read_receipt(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        self.con.execute("CREATE TABLE late_unrelated_source (value TEXT)")
        self.con.commit()
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt), "HOLD")
        # Raw data remains unchanged; refuse authority even when row survived.
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")

    def test_trigger_added_after_open_cannot_ignore_reservation(self):
        self.con.execute("""
            CREATE TRIGGER late_ignore_insert
            BEFORE INSERT ON offline_scope_1454_attempts
            BEGIN SELECT RAISE(IGNORE); END
        """)
        self.con.commit()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_trigger_added_after_open_cannot_mutate_reserved_phase(self):
        self.con.execute("""
            CREATE TRIGGER late_mutate_insert
            AFTER INSERT ON offline_scope_1454_attempts
            BEGIN
                UPDATE offline_scope_1454_attempts
                   SET phase='uncertain' WHERE attempt_id=NEW.attempt_id;
            END
        """)
        self.con.commit()
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "HOLD")
        self.assertEqual(self.count(), 0)

    def test_trigger_added_after_open_cannot_undo_terminal_phase(self):
        self.journal.reserve(self.attempt)
        self.con.execute("""
            CREATE TRIGGER late_undo_update
            AFTER UPDATE ON offline_scope_1454_attempts
            BEGIN
                UPDATE offline_scope_1454_attempts
                   SET phase='reserved' WHERE attempt_id=NEW.attempt_id;
            END
        """)
        self.con.commit()
        self.assert_non_authorizing(
            self.journal.mark_uncertain(self.attempt), "HOLD")
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "unknown")

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
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "unknown")
        self.assertEqual(self.count(), 1)

    def test_wrong_binding_cannot_finish_or_borrow_state(self):
        self.journal.reserve(self.attempt)
        other = dataclasses.replace(
            self.attempt, attempt_id="fixture-other-attempt")
        self.assert_non_authorizing(
            self.journal.mark_recorded(other, "d" * 64), "HOLD")
        self.assertEqual(self.count(), 1)

    def test_mutated_attempt_id_during_reserve_never_gets_review_receipt(self):
        attempt = fixture()
        def tamper(sql):
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                object.__setattr__(
                    attempt, "attempt_id", "fixture-mutated-attempt"
                )
        self.con.set_trace_callback(tamper)
        try:
            receipt = self.journal.reserve(attempt)
        finally:
            self.con.set_trace_callback(None)
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(self.count(), 0)
        self.assertFalse(self.con.in_transaction)

    def test_mutated_run_during_reserve_cannot_claim_valid_provenance(self):
        attempt = fixture()
        def tamper(sql):
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                object.__setattr__(attempt, "run_id", "fixture-mutated-run")
        self.con.set_trace_callback(tamper)
        try:
            receipt = self.journal.reserve(attempt)
        finally:
            self.con.set_trace_callback(None)
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(self.count(), 0)
        self.assertFalse(self.con.in_transaction)

    def test_mutated_grant_during_terminal_transition_is_denied(self):
        attempt = fixture()
        self.journal.reserve(attempt)
        def tamper(sql):
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                object.__setattr__(attempt, "grant_id", "fixture-mutated-grant")
        self.con.set_trace_callback(tamper)
        try:
            receipt = self.journal.mark_recorded(attempt, "a" * 64)
        finally:
            self.con.set_trace_callback(None)
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertEqual(self.con.execute(
            "SELECT phase FROM offline_scope_1454_attempts"
        ).fetchone()[0], "reserved")
        self.assertFalse(self.con.in_transaction)

    def test_mutated_client_during_phase_read_denies_identity(self):
        attempt = fixture()
        self.journal.reserve(attempt)
        def tamper(sql):
            if sql.strip().upper() == "BEGIN":
                object.__setattr__(attempt, "client_id", "fixture-new-client")
        self.con.set_trace_callback(tamper)
        try:
            phase, receipt = self.journal.review_phase(attempt)
        finally:
            self.con.set_trace_callback(None)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertFalse(self.con.in_transaction)

    def test_phase_read_uses_single_explicit_sqlite_snapshot(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        trace = []
        self.con.set_trace_callback(trace.append)
        try:
            phase, receipt = self.journal.review_phase(self.attempt)
        finally:
            self.con.set_trace_callback(None)
        self.assertEqual(phase, "reserved")
        self.assert_non_authorizing(receipt, "REVIEW_ONLY")
        normalized = [line.strip().upper() for line in trace]
        begin = next(i for i, s in enumerate(normalized) if s == "BEGIN")
        schema = next(i for i, s in enumerate(normalized)
                      if "SQLITE_MASTER" in s)
        phase_read = next(i for i, s in enumerate(normalized)
                          if "SELECT SEALED_BINDING" in s)
        rollback = next(i for i, s in enumerate(normalized)
                        if s == "ROLLBACK")
        self.assertLess(begin, schema)
        self.assertLess(schema, phase_read)
        self.assertLess(phase_read, rollback)
        self.assertFalse(self.con.in_transaction)

    def test_backlog_read_uses_single_explicit_sqlite_snapshot(self):
        self.assert_non_authorizing(self.journal.reserve(self.attempt), "REVIEW_ONLY")
        trace = []
        self.con.set_trace_callback(trace.append)
        try:
            report = self.journal.review_backlog().as_dict()
        finally:
            self.con.set_trace_callback(None)
        self.assertEqual(report["status"], "REVIEW_ONLY")
        self.assertEqual(report["reserved_count"], 1)
        normalized = [line.strip().upper() for line in trace]
        begin = next(i for i, s in enumerate(normalized) if s == "BEGIN")
        schema = next(i for i, s in enumerate(normalized)
                      if "SQLITE_MASTER" in s)
        read = next(i for i, s in enumerate(normalized)
                    if "SELECT SEALED_BINDING" in s)
        rollback = next(i for i, s in enumerate(normalized)
                        if s == "ROLLBACK")
        self.assertLess(begin, schema)
        self.assertLess(schema, read)
        self.assertLess(read, rollback)
        self.assertFalse(self.con.in_transaction)

    def test_caller_owned_transaction_never_used_for_phase_read(self):
        self.journal.reserve(self.attempt)
        self.con.execute("BEGIN IMMEDIATE")
        phase, receipt = self.journal.review_phase(self.attempt)
        self.assertEqual(phase, "unknown")
        self.assert_non_authorizing(receipt, "HOLD")
        self.assertTrue(self.con.in_transaction)
        self.con.rollback()
        self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")

    def test_repeat_snapshot_reads_release_transaction_after_each_review(self):
        self.journal.reserve(self.attempt)
        for _ in range(7):
            self.assertEqual(self.journal.review_phase(self.attempt)[0], "reserved")
            self.assertFalse(self.con.in_transaction)
            self.assertEqual(self.journal.review_backlog().as_dict()["reserved_count"], 1)
            self.assertFalse(self.con.in_transaction)
        self.assert_non_authorizing(self.journal.mark_uncertain(self.attempt),
                                    "REVIEW_ONLY")
        self.assertEqual(self.journal.review_backlog().as_dict()["uncertain_count"], 1)

    def test_snapshot_errors_return_hold_without_leaking_counts(self):
        self.journal.reserve(self.attempt)
        self.con.execute("CREATE TABLE late_schema_mutation (fixture TEXT)")
        self.con.commit()
        for _ in range(3):
            phase, receipt = self.journal.review_phase(self.attempt)
            self.assertEqual(phase, "unknown")
            self.assert_non_authorizing(receipt, "HOLD")
            backlog = self.journal.review_backlog().as_dict()
            self.assertEqual(backlog["status"], "HOLD")
            self.assertEqual(backlog["reserved_count"], 0)
            self.assertFalse(self.con.in_transaction)

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
