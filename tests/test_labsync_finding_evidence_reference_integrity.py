from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lightup.domain import AccessContext, DomainStore, Role
from lightup.labsync import ensure_lab_engagement, persist_lab_findings


class _EvidenceList(list):
    pass


class _EvidenceText(str):
    pass


class LabSyncFindingEvidenceReferenceIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-evidence", Role.OPERATOR)
        self.engagement = ensure_lab_engagement(self.store, self.operator)

    def _result(self, *, evidence_ids_marker=... , top_level_evidence_id_marker=...):
        finding = {
            "finding": "Synthetic lab finding",
            "severity": "medium",
            "target": "http://127.0.0.1/",
            "impact": "Synthetic impact",
            "fix": "Synthetic remediation",
        }
        if evidence_ids_marker is not ...:
            finding["evidence_ids"] = evidence_ids_marker

        result = {
            "target": "http://127.0.0.1/",
            "findings": [finding],
        }
        if top_level_evidence_id_marker is not ...:
            result["evidence_id"] = top_level_evidence_id_marker
        return result

    def _stored(self):
        return self.store.list_findings(
            self.operator,
            engagement_id=self.engagement.engagement_id,
        )

    def _assert_rejected_before_record(self, result):
        before = tuple(self._stored())
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
        self.assertEqual(tuple(self._stored()), before)

    def test_canonical_finding_local_evidence_list_remains_green(self):
        records = persist_lab_findings(
            self.store,
            self.operator,
            self.engagement.engagement_id,
            self._result(evidence_ids_marker=["evidence:alpha", "evidence:beta"]),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0].evidence_ids,
            ("evidence:alpha", "evidence:beta"),
        )
        self.assertEqual(self._stored()[0].evidence_ids, records[0].evidence_ids)

    def test_canonical_single_lane_fallback_evidence_id_remains_green(self):
        records = persist_lab_findings(
            self.store,
            self.operator,
            self.engagement.engagement_id,
            self._result(top_level_evidence_id_marker="evidence:fallback"),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].evidence_ids, ("evidence:fallback",))

    def test_finding_local_string_is_not_split_into_character_references(self):
        self._assert_rejected_before_record(
            self._result(evidence_ids_marker="evidence:single")
        )

    def test_finding_local_list_subclass_is_not_normalized(self):
        self._assert_rejected_before_record(
            self._result(
                evidence_ids_marker=_EvidenceList(["evidence:canonical-looking"])
            )
        )

    def test_finding_local_string_subclass_entry_is_rejected(self):
        self._assert_rejected_before_record(
            self._result(
                evidence_ids_marker=[_EvidenceText("evidence:canonical-looking")]
            )
        )

    def test_blank_finding_local_evidence_reference_is_rejected(self):
        self._assert_rejected_before_record(
            self._result(evidence_ids_marker=["   "])
        )

    def test_duplicate_finding_local_evidence_references_are_rejected(self):
        self._assert_rejected_before_record(
            self._result(
                evidence_ids_marker=["evidence:duplicate", "evidence:duplicate"]
            )
        )

    def test_non_string_single_lane_fallback_evidence_id_is_rejected(self):
        self._assert_rejected_before_record(
            self._result(top_level_evidence_id_marker=123)
        )

    def test_blank_single_lane_fallback_evidence_id_is_rejected(self):
        self._assert_rejected_before_record(
            self._result(top_level_evidence_id_marker="   ")
        )


if __name__ == "__main__":
    unittest.main()
