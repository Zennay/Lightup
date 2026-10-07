from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Callable

from lightup.domain import AccessContext, DomainStore, FindingRecord, Role
from lightup.models import Severity


class FindingReadEvidenceSelectorIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-finding-evidence-selectors", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator,
            "Finding selector evidence client",
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Finding selector evidence engagement",
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Selector evidence finding",
            severity=Severity.LOW,
            asset="asset://selector-lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=("evidence:selector",),
        )

    def _replace_evidence_json(self, raw: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def _raw_evidence_json(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["evidence_ids_json"]

    def _selectors(self) -> tuple[tuple[str, Callable[[], list[FindingRecord]]], ...]:
        return (
            (
                "engagement",
                lambda: self.store.list_findings(
                    self.operator,
                    engagement_id=self.engagement.engagement_id,
                ),
            ),
            (
                "client",
                lambda: self.store.list_findings(
                    self.operator,
                    client_id=self.client.client_id,
                ),
            ),
            (
                "operator-wide",
                lambda: self.store.list_findings(self.operator),
            ),
        )

    def test_canonical_evidence_is_readable_through_every_selector(self) -> None:
        for selector_name, read in self._selectors():
            with self.subTest(selector=selector_name):
                records = read()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].finding_id, self.finding.finding_id)
                self.assertEqual(records[0].evidence_ids, ("evidence:selector",))

    def test_malformed_evidence_fails_closed_through_every_selector(self) -> None:
        malformed = '"evidence:selector"'
        self._replace_evidence_json(malformed)
        before = self._raw_evidence_json()

        for selector_name, read in self._selectors():
            with self.subTest(selector=selector_name):
                with self.assertRaisesRegex(ValueError, "evidence"):
                    read()
                self.assertEqual(self._raw_evidence_json(), before)


if __name__ == "__main__":
    unittest.main()
