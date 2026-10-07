from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class FindingReadEvidenceIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-finding-read-evidence", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Evidence read client")
        self.engagement = self.store.create_engagement(
            self.operator,
            client.client_id,
            "Evidence read engagement",
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Evidence-backed finding",
            severity=Severity.MEDIUM,
            asset="asset://lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=("evidence:one", "evidence:two"),
        )

    def _raw_evidence_json(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["evidence_ids_json"]

    def _replace_evidence_json(self, raw: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def _read(self):
        return self.store.list_findings(
            self.operator,
            engagement_id=self.engagement.engagement_id,
        )

    def _assert_rejected_without_mutation(self, raw: str) -> None:
        self._replace_evidence_json(raw)
        before = self._raw_evidence_json()

        with self.assertRaisesRegex(ValueError, "evidence"):
            self._read()

        self.assertEqual(self._raw_evidence_json(), before)

    def test_canonical_evidence_array_remains_green_and_ordered(self) -> None:
        visible = self._read()

        self.assertEqual(len(visible), 1)
        self.assertEqual(
            visible[0].evidence_ids,
            ("evidence:one", "evidence:two"),
        )

    def test_canonical_empty_array_remains_green_for_manual_finding(self) -> None:
        self._replace_evidence_json("[]")

        visible = self._read()

        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0].evidence_ids, ())

    def test_persisted_string_is_not_split_into_character_references(self) -> None:
        self._assert_rejected_without_mutation('"evidence:one"')

    def test_persisted_object_is_not_normalized_to_key_references(self) -> None:
        self._assert_rejected_without_mutation('{"evidence:one": true}')

    def test_non_string_array_item_is_rejected(self) -> None:
        self._assert_rejected_without_mutation('["evidence:one", 7]')

    def test_blank_array_item_is_rejected(self) -> None:
        self._assert_rejected_without_mutation('["   "]')

    def test_duplicate_array_items_are_rejected(self) -> None:
        self._assert_rejected_without_mutation(
            '["evidence:duplicate", "evidence:duplicate"]'
        )


if __name__ == "__main__":
    unittest.main()
