"""#649: offline, source-owner-isolated durable grant issuance provenance contract.

Acceptance only. Synthetic SQLite and names; no sockets, handlers, targets or grants
outside TemporaryDirectory. Original production source is deliberately unchanged.
"""
from __future__ import annotations

import os
import sqlite3
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


def _source_red(test):
    """Opt-in genuine source gate; normal offline CI records unresolved owner REDs."""
    if os.environ.get("LIGHTUP_SCOPE649_REQUIRE_SOURCE_FIX") == "1":
        return test
    return unittest.expectedFailure(test)


class _ToggleStrip(str):
    """Purely synthetic; exposes validation-then-persistence double-read."""
    def __new__(cls, text="synthetic provenance"):
        obj = str.__new__(cls, text)
        obj.calls = 0
        return obj

    def strip(self, *args, **kwargs):
        self.calls += 1
        return "VERIFIED-SYNTHETIC" if self.calls == 1 else ""


class _StringSubclass(str):
    """Noncanonical provenance, even if the resulting text looks harmless."""


class _DuckText:
    """Untrusted object with a fake .strip API; must never impersonate text."""
    def __init__(self):
        self.calls = 0

    def strip(self):
        self.calls += 1
        return "SYNTHETIC-DUCK"


class GrantIssuanceProvenance649(unittest.TestCase):
    def setUp(self):
        # No network or child process is part of any grant provenance test.
        # Scoped patches are restored after every method, including failures.
        for symbol in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen"):
            guard = patch(symbol, side_effect=AssertionError(
                "scope649 fixture unexpectedly attempted network/process I/O"
            ))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-scope649-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic.db"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Synthetic Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Synthetic LAB review"
        )
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(minutes=5)
        self.end = now + timedelta(minutes=5)
        self.scope = ScopeDefinition(
            assets=("unit.example.test",),
            max_risk=RiskLevel.PASSIVE,
            allowed_capabilities=("web-baseline",),
        )

    def _row_count(self):
        with sqlite3.connect(self.path) as con:
            return con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]

    def _issue(self, approved_by="Synthetic operator", reference="SYNTH-649"):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id,
            approved_by, reference, self.scope, self.start, self.end,
        )

    def _reject_without_rows(self, *, approved_by="Synthetic operator", reference="SYNTH-649"):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._issue(approved_by=approved_by, reference=reference)
        self.assertEqual(self._row_count(), before)

    def test_canonical_builtin_strings_are_trimmed_once_for_storage(self):
        grant = self._issue("  Synthetic operator  ", "  SYNTH-649  ")
        self.assertEqual(type(grant.approved_by), str)
        self.assertEqual(type(grant.reference), str)
        self.assertEqual(grant.approved_by, "Synthetic operator")
        self.assertEqual(grant.reference, "SYNTH-649")
        with sqlite3.connect(self.path) as con:
            row = con.execute(
                "SELECT approved_by, reference FROM authorization_grants WHERE grant_id=?",
                (grant.grant_id,),
            ).fetchone()
        self.assertEqual(row, ("Synthetic operator", "SYNTH-649"))
        self.assertEqual(self._row_count(), 1)

    def test_blank_builtin_reference_is_rejected_atomically(self):
        self._reject_without_rows(reference="  \t  ")

    def test_blank_builtin_approver_is_rejected_atomically(self):
        self._reject_without_rows(approved_by="  \n  ")

    def test_healthy_canonical_inputs_do_not_mutate_scope_or_window(self):
        initial = (self.scope, self.start, self.end)
        grant = self._issue()
        self.assertEqual((self.scope, self.start, self.end), initial)
        self.assertEqual(grant.scope, self.scope)

    @_source_red
    def test_rejects_exactly_nonbuiltin_approver_str_subclass(self):
        self._reject_without_rows(approved_by=_StringSubclass("Synthetic operator"))

    @_source_red
    def test_rejects_exactly_nonbuiltin_reference_str_subclass(self):
        self._reject_without_rows(reference=_StringSubclass("SYNTH-649"))

    @_source_red
    def test_rejects_polymorphic_approver_before_two_reads(self):
        value = _ToggleStrip()
        self._reject_without_rows(approved_by=value)
        self.assertEqual(value.calls, 0, "invalid subclass must not be consulted")

    @_source_red
    def test_rejects_polymorphic_reference_before_two_reads(self):
        value = _ToggleStrip()
        self._reject_without_rows(reference=value)
        self.assertEqual(value.calls, 0, "invalid subclass must not be consulted")

    @_source_red
    def test_nonstring_approver_is_rejected_as_validation_error(self):
        self._reject_without_rows(approved_by=7)

    @_source_red
    def test_nonstring_reference_is_rejected_as_validation_error(self):
        self._reject_without_rows(reference=None)

    @_source_red
    def test_rejects_duck_approver_without_consulting_foreign_methods(self):
        value = _DuckText()
        try:
            self._reject_without_rows(approved_by=value)
        finally:
            self.assertEqual(value.calls, 0, "a non-string may not execute .strip")

    @_source_red
    def test_rejects_duck_reference_without_consulting_foreign_methods(self):
        value = _DuckText()
        try:
            self._reject_without_rows(reference=value)
        finally:
            self.assertEqual(value.calls, 0, "a non-string may not execute .strip")

    @_source_red
    def test_rejects_bytes_reference_with_deterministic_validation_error(self):
        self._reject_without_rows(reference=b"SYNTH-649")

    @_source_red
    def test_bad_approver_does_not_create_a_second_grant(self):
        original = self._issue()
        self._reject_without_rows(approved_by=_StringSubclass("Other reviewer"))
        self.assertEqual(self._row_count(), 1)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, self.engagement.engagement_id
            )[0].grant_id, original.grant_id,
        )

    @_source_red
    def test_bad_reference_does_not_overwrite_healthy_provenance(self):
        original = self._issue()
        self._reject_without_rows(reference=_ToggleStrip())
        with sqlite3.connect(self.path) as con:
            pairs = con.execute(
                "SELECT approved_by, reference FROM authorization_grants"
            ).fetchall()
        self.assertEqual(pairs, [(original.approved_by, original.reference)])

    def test_synthetic_durable_drift_is_denied_by_unwired_pair_reviewer(self):
        """Integration of the real local-only source gap with a synthetic HOLD."""
        scripts = str(Path(__file__).resolve().parents[1] / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        import review_scope_grant_provenance_pair_synthetic_649 as compare
        import review_scope_grant_provenance_synthetic_649 as audit

        value = _ToggleStrip()
        before_count = self._row_count()
        try:
            grant = self._issue(reference=value)
        except ValueError:
            # After the independent source owner fixes exact primitive typing,
            # rejection without a durable row is the correct green route.
            self.assertEqual(self._row_count(), before_count)
            return
        # Current unmodified owner source stores a second, blank .strip result.
        with sqlite3.connect(self.path) as con:
            row = con.execute(
                "SELECT reference, approved_by FROM authorization_grants "
                "WHERE grant_id=?", (grant.grant_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertGreaterEqual(value.calls, 2)
        self.assertEqual(row[0], "")
        self.assertEqual(self._row_count(), before_count + 1)
        result = compare.review_pair_batch({
            "schema": compare.PAIR_SCHEMA,
            "synthetic_only": True,
            "pairs": [{
                "before": {
                    "approved_by": "Synthetic operator",
                    "reference": "VERIFIED-SYNTHETIC",
                },
                "after": {"approved_by": row[1], "reference": row[0]},
            }],
        })
        self.assertIs(result.status, audit.ReviewStatus.HOLD)
        self.assertFalse(result)
        self.assertFalse(result.permit_issued)
        self.assertFalse(result.authorization_verified)

    def test_synthetic_approver_drift_from_disposable_db_yields_hold(self):
        """Separate real SQLite read: corrupted approver must be review-only HOLD."""
        scripts = str(Path(__file__).resolve().parents[1] / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        import review_scope_grant_provenance_pair_synthetic_649 as compare
        import review_scope_grant_provenance_synthetic_649 as audit

        dirty_approver = _ToggleStrip()
        initial = self._row_count()
        try:
            grant = self._issue(approved_by=dirty_approver)
        except ValueError:
            self.assertEqual(self._row_count(), initial)
            self.assertEqual(dirty_approver.calls, 0)
            return  # Correct future source-owner exact-builtin-str repair.
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT approved_by, reference FROM authorization_grants "
                "WHERE grant_id=?", (grant.grant_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, ("", "SYNTH-649"))
        self.assertGreaterEqual(dirty_approver.calls, 2)
        self.assertEqual(self._row_count(), initial + 1)
        before = {"approved_by": "VERIFIED-SYNTHETIC", "reference": "SYNTH-649"}
        after = {"approved_by": row[0], "reference": row[1]}
        review = compare.review_pair_batch({
            "schema": compare.PAIR_SCHEMA, "synthetic_only": True,
            "pairs": [{"before": before, "after": after}],
        })
        self.assertIs(review.status, audit.ReviewStatus.HOLD)
        self.assertFalse(review)
        self.assertFalse(review.consent_verified)
        self.assertFalse(review.release_approved)

    def test_canonical_approver_and_reference_repeated_grants_keep_provenance(self):
        first = self._issue()
        second = self._issue(approved_by="Synthetic reviewer B", reference="SYNTH-B")
        self.assertNotEqual(first.grant_id, second.grant_id)
        with sqlite3.connect(self.path) as con:
            pairs = set(con.execute(
                "SELECT approved_by, reference FROM authorization_grants"
            ).fetchall())
        self.assertEqual(pairs, {
            ("Synthetic operator", "SYNTH-649"),
            ("Synthetic reviewer B", "SYNTH-B"),
        })


if __name__ == "__main__":
    unittest.main()
