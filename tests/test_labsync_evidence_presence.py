from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lightup.domain import AccessContext, DomainStore, Role
from lightup.labsync import ensure_lab_engagement, persist_lab_findings


class LabSyncEvidencePresenceAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-evidence-presence", Role.OPERATOR)
        self.engagement = ensure_lab_engagement(self.store, self.operator)

    def _result(self, *, local=..., fallback=...):
        finding = {
            "finding": "Synthetic evidence-backed finding",
            "severity": "medium",
            "target": "http://127.0.0.1/",
            "impact": "Synthetic impact",
            "fix": "Synthetic remediation",
        }
        if local is not ...:
            finding["evidence_ids"] = local

        result = {
            "target": "http://127.0.0.1/",
            "findings": [finding],
        }
        if fallback is not ...:
            result["evidence_id"] = fallback
        return result

    def _stored(self):
        return tuple(
            self.store.list_findings(
                self.operator,
                engagement_id=self.engagement.engagement_id,
            )
        )

    def _assert_missing_evidence_rejected_before_write(self, result):
        before = self._stored()
        with mock.patch.object(
            self.store,
            "record_finding",
            wraps=self.store.record_finding,
        ) as record_finding:
            with self.assertRaisesRegex(ValueError, "evidence"):
                persist_lab_findings(
                    self.store,
                    self.operator,
                    self.engagement.engagement_id,
                    result,
                )
            record_finding.assert_not_called()
        self.assertEqual(self._stored(), before)

    def test_planner_driven_finding_local_evidence_remains_green(self):
        records = persist_lab_findings(
            self.store,
            self.operator,
            self.engagement.engagement_id,
            self._result(local=["evidence:planner-1"]),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].evidence_ids, ("evidence:planner-1",))

    def test_single_lane_top_level_fallback_remains_green(self):
        records = persist_lab_findings(
            self.store,
            self.operator,
            self.engagement.engagement_id,
            self._result(fallback="single-lane-evidence-id"),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].evidence_ids, ("single-lane-evidence-id",))

    def test_empty_local_list_still_uses_valid_top_level_fallback(self):
        records = persist_lab_findings(
            self.store,
            self.operator,
            self.engagement.engagement_id,
            self._result(local=[], fallback="single-lane-fallback"),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].evidence_ids, ("single-lane-fallback",))

    def test_missing_both_evidence_sources_fails_closed(self):
        self._assert_missing_evidence_rejected_before_write(self._result())

    def test_empty_local_list_without_fallback_fails_closed(self):
        self._assert_missing_evidence_rejected_before_write(
            self._result(local=[])
        )


if __name__ == "__main__":
    unittest.main()
