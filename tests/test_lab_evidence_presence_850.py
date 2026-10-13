"""#850 real-SQLite synthetic lab evidence presence acceptance (no HTTP/DNS).

Source-owner lab bridge remains unchanged. RED tests are unresolved #850
acceptance, not a claim that missing evidence is already rejected.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.labsync import ensure_lab_engagement, persist_lab_findings


class LabEvidencePresenceAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "lab-evidence.db"
        self.store = DomainStore(self.db_path)
        self.operator = AccessContext("lab-operator", Role.OPERATOR)
        self.engagement = ensure_lab_engagement(self.store, self.operator)

    def _finding(self, **overrides):
        item = {
            "finding": "Synthetic missing CSP",
            "severity": "medium",
            "target": "http://127.0.0.1/",
            "impact": "Synthetic impact",
            "fix": "Synthetic remediation",
        }
        item.update(overrides)
        return item

    def _run(self, finding, *, evidence_id=None):
        result = {
            "target": "http://127.0.0.1/",
            "findings": [finding],
        }
        if evidence_id is not None:
            result["evidence_id"] = evidence_id
        return persist_lab_findings(
            self.store, self.operator, self.engagement.engagement_id, result
        )

    def _durable_rows(self):
        # An independent SQLite connection proves durable, not mock-only state.
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                "SELECT finding_id, evidence_ids_json FROM findings "
                "WHERE engagement_id=? ORDER BY finding_id",
                (self.engagement.engagement_id,),
            ).fetchall()
        return rows

    def test_finding_local_evidence_survives_to_durable_record(self):
        rows = self._run(
            self._finding(evidence_ids=["ev:local-1", "ev:local-2"]),
            evidence_id="ev:legacy-ignored",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].evidence_ids, ("ev:local-1", "ev:local-2"))
        stored = self._durable_rows()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0][1], '["ev:local-1", "ev:local-2"]')

    def test_absent_local_evidence_preserves_legacy_top_level_fallback(self):
        rows = self._run(self._finding(), evidence_id="ev:legacy")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].evidence_ids, ("ev:legacy",))
        self.assertEqual(len(self._durable_rows()), 1)
        self.assertEqual(self._durable_rows()[0][1], '["ev:legacy"]')

    def test_explicit_empty_local_evidence_keeps_valid_legacy_fallback(self):
        rows = self._run(self._finding(evidence_ids=[]), evidence_id="ev:legacy")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].evidence_ids, ("ev:legacy",))
        self.assertEqual(self._durable_rows()[0][1], '["ev:legacy"]')

    def _assert_missing_ref_rejected_without_write(self, finding):
        before = self._durable_rows()
        with patch.object(
            self.store, "record_finding", wraps=self.store.record_finding
        ) as record:
            try:
                with self.assertRaisesRegex(ValueError, "[Ee]vidence"):
                    self._run(finding)
            finally:
                self.assertEqual(self._durable_rows(), before)
                record.assert_not_called()

    @unittest.expectedFailure  # #850 source owner has not installed presence gate
    def test_no_local_or_legacy_evidence_refuses_before_record_finding(self):
        self._assert_missing_ref_rejected_without_write(self._finding())

    @unittest.expectedFailure  # #850 source owner has not installed presence gate
    def test_empty_local_without_legacy_refuses_before_record_finding(self):
        self._assert_missing_ref_rejected_without_write(self._finding(evidence_ids=[]))


if __name__ == "__main__":
    unittest.main()
