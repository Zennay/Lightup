"""Expected-RED synthetic retest evidence reference perceptibility checks.

No verified retests: this only exercises the opt-in metadata sidecar with
disposable SQLite records. The installed source/authorization paths are untouched.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import RetestStatus, Severity
from lightup.retest_status_atomic_sidecar import atomic_retest_status_metadata


class EvidenceReferenceMarkOnlyRed(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = DomainStore(Path(temp.name) / "retest-lab.sqlite")
        self.operator = AccessContext("offline-synthetic-operator", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Synthetic retest lab")
        eng = self.store.create_engagement(
            self.operator, self.client.client_id, "Synthetic review"
        )
        self.finding = self.store.record_finding(
            self.operator, eng.engagement_id, "Synthetic finding", Severity.MEDIUM,
            "lab.invalid", "No real exposure", "Review then retest",
            ("evidence:one",),
        )

    def _set_evidence(self, values):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (json.dumps(values), self.finding.finding_id),
            )

    def _snapshot(self):
        with self.store._connect() as con:
            return tuple(con.execute(
                "SELECT retest_status,evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone())

    def _transition(self):
        return atomic_retest_status_metadata(
            self.store, self.operator,
            self.finding.finding_id, RetestStatus.FIX_PENDING,
        )

    def test_single_nonperceptible_reference_must_not_be_counted_as_evidence(self):
        for value in ("\u0301", "\u20dd", "\ufe0f", "\u0903"):
            with self.subTest(value=ascii(value)):
                self._set_evidence([value])
                before = self._snapshot()
                with self.assertRaisesRegex(ValueError, "finding evidence"):
                    self._transition()
                self.assertEqual(before, self._snapshot())

    def test_late_mark_only_reference_aborts_whole_transaction(self):
        self._set_evidence(["real-ref-01", "real-ref-02", "\ufe0f"])
        before = self._snapshot()
        with self.assertRaisesRegex(ValueError, "finding evidence"):
            self._transition()
        self.assertEqual(before, self._snapshot())

    def test_compatibility_modifier_becomes_only_mark_after_nfkc(self):
        for value in ("\uff9e", "\uff9f", "\u00b4"):
            with self.subTest(value=ascii(value)):
                self._set_evidence([value])
                before = self._snapshot()
                with self.assertRaisesRegex(ValueError, "finding evidence"):
                    self._transition()
                self.assertEqual(before, self._snapshot())

    def test_valid_reference_with_accent_or_variation_selector_is_preserved(self):
        for value in ("ref-cafe\u0301", "ref-🎯\ufe0f", "ref-7\u20dd"):
            with self.subTest(value=ascii(value)):
                self._set_evidence([value])
                record = self._transition()
                self.assertIs(record.retest_status, RetestStatus.FIX_PENDING)
                self.assertEqual(record.evidence_ids, (value,))
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE findings SET retest_status=? WHERE finding_id=?",
                        (RetestStatus.NOT_TESTED.value, self.finding.finding_id),
                    )

    def test_empty_evidence_is_still_legal_for_unverified_triage(self):
        self._set_evidence([])
        record = self._transition()
        self.assertEqual(record.evidence_ids, ())
        self.assertIs(record.retest_status, RetestStatus.FIX_PENDING)


if __name__ == "__main__":
    unittest.main()
