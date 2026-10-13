"""Synthetic, offline #849 FindingRecord exact-object admission acceptance.

No real network observation: all baseline.observe calls are patched.
Unfixed polymorphic safety requirements are intentional expected failures.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, FindingRecord, Role
from lightup.labeval import LabIsolationError
from lightup.labsync import ensure_lab_engagement, retest_finding
from lightup.models import RetestStatus, Severity
from lightup.workers import http_baseline


class EqualitySpoofFinding(FindingRecord):
    # Producer-impossible identity; never accepted as a durable domain row.
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class TitleReadTrapFinding(FindingRecord):
    def __getattribute__(self, name):
        if name == "title":
            raise AssertionError("untrusted subclass title accessed before admission")
        return super().__getattribute__(name)


class LabRetestObjectIdentityAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "lab-retest.db"
        self.store = DomainStore(self.db_path)
        self.operator = AccessContext("lab-operator", Role.OPERATOR)
        self.engagement = ensure_lab_engagement(self.store, self.operator)
        self.canonical_title = http_baseline.BASELINE_CHECKS[0][2]
        self.other_title = http_baseline.BASELINE_CHECKS[1][2]
        self.assertNotEqual(self.canonical_title, self.other_title)
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            self.canonical_title,
            Severity.MEDIUM,
            "http://127.0.0.1/",
            "Synthetic impact",
            "Synthetic remediation",
        )

    def _row(self):
        # Real on-disk query, distinct from in-memory mutated caller object.
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT finding_id,title,retest_status,evidence_ids_json "
                "FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def _spoof(self, subtype, **changes):
        fields = vars(self.finding).copy()
        fields.update(changes)
        return subtype(**fields)

    def test_exact_current_finding_can_be_retested_with_mocked_observation(self):
        with patch(
            "lightup.labsync.http_baseline.observe",
            return_value=SimpleNamespace(issues=[]),
        ) as observe:
            retested = retest_finding(self.store, self.operator, self.finding)
        observe.assert_called_once_with("http://127.0.0.1/")
        self.assertIs(retested.retest_status, RetestStatus.FIXED)
        self.assertEqual(self._row()[2], RetestStatus.FIXED.value)

    def test_existing_provenance_gate_rejects_nonlab_before_observation(self):
        customer = self.store.create_client(self.operator, "Other synthetic customer")
        engagement = self.store.create_engagement(
            self.operator, customer.client_id, "Not a lab"
        )
        foreign = self.store.record_finding(
            self.operator, engagement.engagement_id, self.canonical_title,
            Severity.LOW, "http://127.0.0.1/", "impact", "fix"
        )
        with patch("lightup.labsync.http_baseline.observe") as observe:
            with self.assertRaises(LabIsolationError):
                retest_finding(self.store, self.operator, foreign)
            observe.assert_not_called()

    @unittest.expectedFailure  # RED: #849 source owner must enforce exact type
    def test_equality_spoof_cannot_change_retest_check_identity(self):
        spoof = self._spoof(EqualitySpoofFinding, title=self.other_title)
        before = self._row()
        with patch(
            "lightup.labsync.http_baseline.observe",
            return_value=SimpleNamespace(issues=[]),
        ) as observe:
            try:
                with self.assertRaises(LabIsolationError):
                    retest_finding(self.store, self.operator, spoof)
            finally:
                observe.assert_not_called()
                self.assertEqual(self._row(), before)
                self.assertEqual(spoof.title, self.other_title)

    @unittest.expectedFailure  # RED: an exact-type gate must run before title access
    def test_polymorphic_title_is_not_read_before_rejection(self):
        spoof = self._spoof(TitleReadTrapFinding)
        before = self._row()
        with patch("lightup.labsync.http_baseline.observe") as observe:
            try:
                with self.assertRaises(LabIsolationError):
                    retest_finding(self.store, self.operator, spoof)
            finally:
                observe.assert_not_called()
                self.assertEqual(self._row(), before)

    @unittest.expectedFailure  # RED: even same-valued subclass must be denied
    def test_same_values_in_subclass_are_never_accepted(self):
        spoof = self._spoof(EqualitySpoofFinding)
        before = self._row()
        with patch("lightup.labsync.http_baseline.observe") as observe:
            try:
                with self.assertRaises(LabIsolationError):
                    retest_finding(self.store, self.operator, spoof)
            finally:
                observe.assert_not_called()
                self.assertEqual(self._row(), before)


if __name__ == "__main__":
    unittest.main()
