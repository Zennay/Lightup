from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class FindingPersistenceEvidenceIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-finding-evidence", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Evidence client")
        self.engagement = self.store.create_engagement(
            self.operator,
            client.client_id,
            "Evidence engagement",
        )

    def _stored(self):
        return tuple(
            self.store.list_findings(
                self.operator,
                engagement_id=self.engagement.engagement_id,
            )
        )

    def _record(self, evidence_ids):
        return self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Evidence-backed finding",
            severity=Severity.MEDIUM,
            asset="asset://lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=evidence_ids,
        )

    def _assert_rejected_without_write(self, evidence_ids):
        before = self._stored()
        with self.assertRaisesRegex(ValueError, "evidence"):
            self._record(evidence_ids)
        self.assertEqual(self._stored(), before)

    def test_exact_non_empty_tuple_of_exact_strings_remains_green(self):
        record = self._record(("evidence:one", "evidence:two"))

        self.assertEqual(record.evidence_ids, ("evidence:one", "evidence:two"))
        stored = self._stored()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].evidence_ids, record.evidence_ids)

    def test_empty_evidence_tuple_is_rejected(self):
        self._assert_rejected_without_write(())

    def test_list_input_is_not_normalized_to_tuple(self):
        self._assert_rejected_without_write(["evidence:one"])

    def test_tuple_subclass_is_not_normalized(self):
        self._assert_rejected_without_write(_EvidenceTuple(("evidence:one",)))

    def test_bare_string_is_not_split_into_character_references(self):
        self._assert_rejected_without_write("evidence:one")

    def test_string_subclass_reference_is_rejected(self):
        self._assert_rejected_without_write((_EvidenceText("evidence:one"),))

    def test_blank_reference_is_rejected(self):
        self._assert_rejected_without_write(("   ",))

    def test_duplicate_references_are_rejected(self):
        self._assert_rejected_without_write(
            ("evidence:duplicate", "evidence:duplicate")
        )


if __name__ == "__main__":
    unittest.main()
