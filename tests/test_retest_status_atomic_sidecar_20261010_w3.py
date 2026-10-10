"""Offline disposable-SQLite acceptance for opt-in remediation status atomicity."""

from __future__ import annotations

import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import replace
import unittest
from pathlib import Path
from unittest import mock

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.models import RetestStatus, Severity
from lightup.retest_status_atomic_sidecar import atomic_retest_status_metadata


class AtomicRetestMetadataSidecarTest(unittest.TestCase):
    def setUp(self) -> None:
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.store = DomainStore(Path(work.name) / "synthetic.db")
        self.operator = AccessContext("offline-operator", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Disposable case")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Disposable engagement"
        )
        self.finding = self._make_finding("Canonical finding")

    def _make_finding(self, title: str):
        return self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title=title,
            severity=Severity.HIGH,
            asset="lab://synthetic-no-target",
            impact="Inert synthetic issue",
            remediation="Human review of synthetic evidence",
            evidence_ids=("evidence:one", "evidence:two"),
        )

    def _row(self, finding_id: str | None = None):
        with self.store._connect() as con:
            return tuple(
                con.execute(
                    "SELECT retest_status,evidence_ids_json,client_id,engagement_id "
                    "FROM findings WHERE finding_id=?",
                    (finding_id or self.finding.finding_id,),
                ).fetchone()
            )

    def _corrupt(self, payload: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (payload, self.finding.finding_id),
            )

    def _transition(self, status=RetestStatus.FIX_PENDING):
        return atomic_retest_status_metadata(
            self.store, self.operator, self.finding.finding_id, status
        )

    def test_valid_synthetic_transition_updates_only_status(self):
        before = self._row()
        result = self._transition()
        after = self._row()
        self.assertIs(result.retest_status, RetestStatus.FIX_PENDING)
        self.assertEqual(result.evidence_ids, ("evidence:one", "evidence:two"))
        self.assertEqual(after[0], RetestStatus.FIX_PENDING.value)
        self.assertEqual(after[1:], before[1:])

    def test_valid_empty_evidence_remains_supported_for_domain_records(self):
        f = self.store.record_finding(
            self.operator, self.engagement.engagement_id, "Manual report",
            Severity.LOW, "lab://synthetic", "None", "Human triage",
        )
        result = atomic_retest_status_metadata(
            self.store, self.operator, f.finding_id, RetestStatus.FIX_PENDING
        )
        self.assertEqual(result.evidence_ids, ())

    def test_only_review_pending_states_are_metadata_only(self):
        for status in (RetestStatus.NOT_TESTED, RetestStatus.FIX_PENDING):
            with self.subTest(status=status):
                result = self._transition(status)
                self.assertIs(result.retest_status, status)

    def test_unverified_retest_outcomes_cannot_be_minted(self):
        before = self._full_row()
        for status in (RetestStatus.FIXED, RetestStatus.REGRESSION):
            with self.subTest(status=status):
                with mock.patch.object(
                    self.store, "_connect",
                    side_effect=AssertionError("forbidden outcome opened SQLite"),
                ):
                    with self.assertRaisesRegex(
                        ValueError, "independent retest evidence"
                    ):
                        self._transition(status)
                self.assertEqual(self._full_row(), before)

    def test_review_status_cannot_downgrade_pending_or_prior_outcome(self):
        # These pre-existing labels were injected into disposable fixtures,
        # not minted by the non-verifying sidecar.
        cases = (
            (RetestStatus.FIX_PENDING, RetestStatus.NOT_TESTED),
            (RetestStatus.FIXED, RetestStatus.FIX_PENDING),
            (RetestStatus.FIXED, RetestStatus.NOT_TESTED),
            (RetestStatus.REGRESSION, RetestStatus.FIX_PENDING),
            (RetestStatus.REGRESSION, RetestStatus.NOT_TESTED),
        )
        for prior, requested in cases:
            with self.subTest(prior=prior, requested=requested):
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE findings SET retest_status=? WHERE finding_id=?",
                        (prior.value, self.finding.finding_id),
                    )
                before = self._full_row()
                with self.assertRaisesRegex(ValueError, "requires review"):
                    self._transition(requested)
                self.assertEqual(self._full_row(), before)

    def test_decoder_cannot_smuggle_future_status_into_metadata_transition(self):
        # The persisted raw enum value is valid; simulate a later source
        # decoder/model introducing a new outcome or noncanonical enum object.
        # An allowlist must refuse it, even if its value would pass old CAS.
        original = DomainStore._finding_from_row

        class SyntheticFutureOutcome:
            value = RetestStatus.NOT_TESTED.value

        def decoded_future_state(row):
            return replace(
                original(row), retest_status=SyntheticFutureOutcome()
            )

        before = self._full_row()
        with mock.patch.object(
            DomainStore, "_finding_from_row", side_effect=decoded_future_state
        ):
            with self.assertRaisesRegex(ValueError, "requires review"):
                self._transition(RetestStatus.FIX_PENDING)
        self.assertEqual(self._full_row(), before)

    def test_repeated_pending_review_is_write_free_even_under_abort_trigger(self):
        self._transition(RetestStatus.FIX_PENDING)
        before = self._full_row()
        with self.store._connect() as con:
            con.execute(
                "CREATE TRIGGER synthetic_write_sentinel "
                "BEFORE UPDATE ON findings BEGIN "
                "SELECT RAISE(ABORT, 'repeat attempted SQLite write'); END"
            )
        try:
            again = self._transition(RetestStatus.FIX_PENDING)
            self.assertIs(again.retest_status, RetestStatus.FIX_PENDING)
            self.assertEqual(self._full_row(), before)
        finally:
            with self.store._connect() as con:
                con.execute("DROP TRIGGER synthetic_write_sentinel")

    def test_not_tested_repeat_is_write_free_even_under_abort_trigger(self):
        before = self._full_row()
        with self.store._connect() as con:
            con.execute(
                "CREATE TRIGGER synthetic_write_sentinel "
                "BEFORE UPDATE ON findings BEGIN "
                "SELECT RAISE(ABORT, 'repeat attempted SQLite write'); END"
            )
        try:
            same = self._transition(RetestStatus.NOT_TESTED)
            self.assertIs(same.retest_status, RetestStatus.NOT_TESTED)
            self.assertEqual(self._full_row(), before)
        finally:
            with self.store._connect() as con:
                con.execute("DROP TRIGGER synthetic_write_sentinel")

    def test_malformed_evidence_rejection_is_atomic(self):
        cases = (
            '"evidence:one"', "null", '{"id":"evidence:one"}',
            '["evidence:one"', '[null]', '[1]', '[false]',
            '["evidence:one", "evidence:one"]', '[""]', '[" space "]',
            '["embedded\\nline"]', '["evil\\u0000byte"]',
            '["' + "A" * 257 + '"]',
            '["' + "x" * 257 * 128 + '"]',
        )
        for payload in cases:
            with self.subTest(payload=payload[:48]):
                self._corrupt(payload)
                before = self._row()
                with self.assertRaisesRegex(ValueError, "finding evidence"):
                    self._transition()
                self.assertEqual(self._row(), before)

    def test_sql_shape_guard_denies_large_or_nontext_evidence_before_full_read(self):
        # Trace statements rather than guessing from exceptions: malformed
        # historical evidence must be rejected BEFORE SELECT f.* materializes
        # unbounded bytes from the persisted row into Python memory.
        cases = (
            ("huge_ascii", "A" * 300_000),
            ("multibyte_utf8", "é" * 9_000),
            ("sqlite_blob", sqlite3.Binary(b'["evidence:one"]')),
        )
        for label, raw in cases:
            with self.subTest(label=label):
                self._corrupt(raw)
                before = self._row()
                statements = []
                original_connect = self.store._connect

                @contextmanager
                def traced_connect():
                    with original_connect() as con:
                        con.set_trace_callback(statements.append)
                        yield con

                with mock.patch.object(
                    self.store, "_connect", side_effect=traced_connect
                ):
                    with self.assertRaisesRegex(ValueError, "finding evidence"):
                        self._transition()
                self.assertFalse(
                    any("SELECT f.*" in sql for sql in statements),
                    "unbounded finding data materialized before SQL guard",
                )
                self.assertTrue(
                    any("length(CAST" in sql for sql in statements),
                    "preflight evidence length guard must execute",
                )
                self.assertEqual(self._row(), before)

    def test_legacy_invalid_retest_labels_deny_before_row_decode_without_leak(self):
        cases = (
            ("invalid_literal", "wrong-status"),
            ("oversized_secret", "PRIVATE_MARKER_" + "Z" * 300_000),
            ("sqlite_blob", sqlite3.Binary(b"fix_pending")),
        )
        for label, raw in cases:
            with self.subTest(label=label):
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE findings SET retest_status=? WHERE finding_id=?",
                        (raw, self.finding.finding_id),
                    )
                before = self._row()
                statements = []
                original_connect = self.store._connect

                @contextmanager
                def traced_connect():
                    with original_connect() as con:
                        con.set_trace_callback(statements.append)
                        yield con

                with mock.patch.object(
                    self.store, "_connect", side_effect=traced_connect
                ):
                    with self.assertRaisesRegex(
                        ValueError, "^finding status is invalid$"
                    ) as caught:
                        self._transition()
                self.assertNotIn("PRIVATE_MARKER_", str(caught.exception))
                self.assertFalse(
                    any("SELECT f.*" in sql for sql in statements),
                    "corrupt legacy status fetched as full row before guard",
                )
                self.assertEqual(self._row(), before)

    def test_rejected_status_and_identity_inputs_never_write(self):
        before = self._row()
        client = AccessContext("client-user", Role.CLIENT_ADMIN, self.client.client_id)
        inputs = (
            (self.store, client, self.finding.finding_id, RetestStatus.FIX_PENDING),
            (self.store, self.operator, self.finding.finding_id, "fixed"),
            (self.store, self.operator, 3, RetestStatus.FIX_PENDING),
            (self.store, self.operator, "", RetestStatus.FIX_PENDING),
            (self.store, "operator", self.finding.finding_id, RetestStatus.FIX_PENDING),
        )
        for args in inputs:
            with self.subTest(args=type(args[1]).__name__):
                with self.assertRaises((RoleError, TypeError, ValueError)):
                    atomic_retest_status_metadata(*args)
                self.assertEqual(self._row(), before)

    def test_noncanonical_finding_identity_and_operator_label_deny_early(self):
        before = self._full_row()
        identities = (
            " " + self.finding.finding_id,
            self.finding.finding_id + " ",
            "   ",
            "\n" + self.finding.finding_id,
        )
        for candidate in identities:
            with self.subTest(candidate=repr(candidate)[:20]):
                with mock.patch.object(
                    self.store, "_connect",
                    side_effect=AssertionError("invalid identity opened SQLite"),
                ):
                    with self.assertRaisesRegex(ValueError, "invalid finding id"):
                        atomic_retest_status_metadata(
                            self.store, self.operator, candidate,
                            RetestStatus.FIX_PENDING,
                        )
        for label in (" operator", "operator ", "  "):
            with self.subTest(label=repr(label)):
                with mock.patch.object(
                    self.store, "_connect",
                    side_effect=AssertionError("invalid operator opened SQLite"),
                ):
                    with self.assertRaises(RoleError):
                        atomic_retest_status_metadata(
                            self.store,
                            AccessContext(label, Role.OPERATOR),
                            self.finding.finding_id,
                            RetestStatus.FIX_PENDING,
                        )
        self.assertEqual(self._full_row(), before)

    def test_missing_finding_never_mutates_other_rows(self):
        other = self._make_finding("Other synthetic finding")
        before = (self._row(), self._row(other.finding_id))
        with self.assertRaises(KeyError):
            atomic_retest_status_metadata(
                self.store, self.operator, "not-a-real-finding", RetestStatus.FIX_PENDING
            )
        self.assertEqual((self._row(), self._row(other.finding_id)), before)

    def test_foreign_client_id_mismatch_rejects_without_write(self):
        other = self.store.create_client(self.operator, "Foreign client")
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET client_id=? WHERE finding_id=?",
                (other.client_id, self.finding.finding_id),
            )
        before = self._row()
        with self.assertRaises(KeyError):
            self._transition()
        self.assertEqual(self._row(), before)

    def test_invalid_severity_decode_failure_rolls_back(self):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET severity=? WHERE finding_id=?",
                ("corrupt-severity", self.finding.finding_id),
            )
        before = self._row()
        with self.assertRaises(ValueError):
            self._transition()
        self.assertEqual(self._row(), before)

    def test_sqlite_trigger_cannot_modify_finding_identity_or_evidence(self):
        # Synthetic trigger fixtures emulate an unexpected SQLite side effect.
        # A status-only metadata helper must reject even a reformat of the
        # very same evidence values, preserving exact stored evidence bytes.
        foreign = self.store.create_client(self.operator, "Trigger foreign tenant")
        cases = (
            ("title", "'Tampered title'"),
            ("remediation", "'Tampered fix advice'"),
            ("client_id", "'" + foreign.client_id + "'"),
            ("evidence_ids_json", "'[ \"evidence:one\", \"evidence:two\" ]'"),
            ("created_at", "'2030-01-01T00:00:00+00:00'"),
        )
        for column, sql_literal in cases:
            with self.subTest(column=column):
                with self.store._connect() as con:
                    con.execute(
                        "CREATE TRIGGER synthetic_retest_row_guard "
                        "AFTER UPDATE OF retest_status ON findings "
                        "BEGIN UPDATE findings SET " + column + "=" + sql_literal +
                        " WHERE finding_id=NEW.finding_id; END"
                    )
                before = self._full_row()
                try:
                    with self.assertRaisesRegex(
                        ValueError, "(finding changed during retest metadata update|unexpected retest transaction write)"
                    ):
                        self._transition()
                    self.assertEqual(self._full_row(), before)
                finally:
                    with self.store._connect() as con:
                        con.execute("DROP TRIGGER synthetic_retest_row_guard")

    def test_trigger_writes_to_another_finding_also_roll_back(self):
        other = self._make_finding("Unaffected sibling")
        own_before = self._full_row()
        with self.store._connect() as con:
            sibling_before = tuple(
                con.execute(
                    "SELECT * FROM findings WHERE finding_id=?", (other.finding_id,)
                ).fetchone()
            )
            con.execute(
                "CREATE TRIGGER synthetic_cross_row_retest "
                "AFTER UPDATE OF retest_status ON findings "
                "BEGIN UPDATE findings SET remediation='unauthorized trigger change' "
                "WHERE finding_id='" + other.finding_id + "'; END"
            )
        try:
            with self.assertRaisesRegex(
                ValueError, "unexpected retest transaction write"
            ):
                self._transition()
        finally:
            with self.store._connect() as con:
                sibling_after = tuple(
                    con.execute(
                        "SELECT * FROM findings WHERE finding_id=?", (other.finding_id,)
                    ).fetchone()
                )
                con.execute("DROP TRIGGER synthetic_cross_row_retest")
        self.assertEqual(self._full_row(), own_before)
        self.assertEqual(sibling_after, sibling_before)

    def _full_row(self):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT * FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
            return tuple(row)

    def test_held_writer_lock_rejects_without_state_change(self):
        @contextmanager
        def fast_connect():
            con = sqlite3.connect(self.store.path, timeout=0.01, isolation_level=None)
            con.row_factory = sqlite3.Row
            try:
                yield con
            finally:
                con.close()

        with sqlite3.connect(self.store.path, isolation_level=None) as writer:
            writer.execute("BEGIN IMMEDIATE")
            before = self._row()
            original = self.store._connect
            self.store._connect = fast_connect
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    self._transition()
            finally:
                self.store._connect = original
                writer.rollback()
            self.assertEqual(self._row(), before)

    def test_post_update_decode_exception_also_rolls_back(self):
        original = DomainStore._finding_from_row
        calls = [0]

        def fail_after_write(row):
            calls[0] += 1
            if calls[0] == 2:
                raise ValueError("synthetic decoder rejection")
            return original(row)

        before = self._row()
        with mock.patch.object(DomainStore, "_finding_from_row", side_effect=fail_after_write):
            with self.assertRaisesRegex(ValueError, "synthetic decoder"):
                self._transition()
        self.assertEqual(calls[0], 2)
        self.assertEqual(self._row(), before)

    def test_unpaired_unicode_surrogate_is_rejected_without_write(self):
        self._corrupt('["\\ud800"]')
        before = self._row()
        with self.assertRaisesRegex(ValueError, "finding evidence"):
            self._transition()
        self.assertEqual(self._row(), before)

    @unittest.expectedFailure
    def test_red_existing_domainstore_still_updates_before_corrupt_decode(self):
        # Expected RED against existing source; cannot be considered closed.
        # This invalid JSON raises only AFTER the legacy autocommit UPDATE.
        # Expected RED specifically detects durable partial mutation, not
        # merely the absence of strict evidence-shape validation.
        self._corrupt('["evidence:one"')
        before = self._row()
        with self.assertRaises(ValueError):
            self.store.set_retest_status(
                self.operator, self.finding.finding_id, RetestStatus.FIXED
            )
        self.assertEqual(self._row(), before)


if __name__ == "__main__":
    unittest.main()
