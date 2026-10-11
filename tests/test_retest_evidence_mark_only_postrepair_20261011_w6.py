"""Independent synthetic evidence-reference admission on opt-in atomic sidecar.

No installed status entrypoint, actual remediation, verification or target work.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity, RetestStatus
from lightup.retest_status_atomic_sidecar import atomic_retest_status_metadata


class RetestEvidencePostrepair(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = DomainStore(Path(temp.name) / "isolated.sqlite")
        self.op = AccessContext("synthetic-operator", Role.OPERATOR)
        client = self.store.create_client(self.op, "Synthetic review org")
        eng = self.store.create_engagement(self.op, client.client_id, "Lab-only")
        self.finding = self.store.record_finding(
            self.op, eng.engagement_id, "Lab evidence", Severity.LOW,
            "lab.invalid", "Inert impact", "Review first", ("ref-001",),
        )

    def patch_ids(self, values):
        with self.store._connect() as db:
            db.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (json.dumps(values), self.finding.finding_id),
            )

    def snapshot(self):
        with self.store._connect() as db:
            return tuple(db.execute(
                "SELECT retest_status,evidence_ids_json,title,engagement_id "
                "FROM findings WHERE finding_id=?", (self.finding.finding_id,),
            ).fetchone())

    def call(self, status=RetestStatus.FIX_PENDING):
        return atomic_retest_status_metadata(
            self.store, self.op, self.finding.finding_id, status,
        )

    def test_supplementary_unicode_mark_only_is_not_evidence(self):
        for text in ("\u1ab0", "\U0001d185", "\U000e0100", "\u034f"):
            with self.subTest(text=ascii(text)):
                self.patch_ids([text])
                before = self.snapshot()
                with self.assertRaisesRegex(ValueError, "finding evidence"):
                    self.call()
                self.assertEqual(self.snapshot(), before)

    def test_unclean_last_reference_cannot_update_any_retest_metadata(self):
        self.patch_ids(["real-ref-a", "real-ref-b", "\uff9f"])
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "finding evidence"):
            self.call()
        self.assertEqual(self.snapshot(), before)

    def test_composed_legitimate_reference_and_empty_references_remain_valid(self):
        for value in ("ref-Cafe\u0301", "ref-🍋\ufe0f", "ref-A\u20dd"):
            with self.subTest(value=ascii(value)):
                self.patch_ids([value])
                result = self.call()
                self.assertEqual(result.evidence_ids, (value,))
                self.assertIs(result.retest_status, RetestStatus.FIX_PENDING)
                with self.store._connect() as db:
                    db.execute(
                        "UPDATE findings SET retest_status=? WHERE finding_id=?",
                        (RetestStatus.NOT_TESTED.value, self.finding.finding_id),
                    )
        self.patch_ids([])
        result = self.call()
        self.assertEqual(result.evidence_ids, ())

    def test_review_metadata_never_mints_verified_outcome(self):
        self.patch_ids(["reference-ok"])
        before = self.snapshot()
        for outcome in (RetestStatus.FIXED, RetestStatus.REGRESSION):
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(ValueError, "independent retest evidence"):
                    self.call(outcome)
                self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
