"""Offline disposable-SQLite acceptance for opt-in remediation status atomicity."""

from __future__ import annotations

import sqlite3
import tempfile
from contextlib import contextmanager
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

    def test_all_synthetic_enum_states_are_metadata_only(self):
        for status in RetestStatus:
            with self.subTest(status=status):
                result = self._transition(status)
                self.assertIs(result.retest_status, status)

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

    def test_missing_finding_never_mutates_other_rows(self):
        other = self._make_finding("Other synthetic finding")
        before = (self._row(), self._row(other.finding_id))
        with self.assertRaises(KeyError):
            atomic_retest_status_metadata(
                self.store, self.operator, "not-a-real-finding", RetestStatus.FIXED
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
