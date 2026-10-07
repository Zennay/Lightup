from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class FindingReadEvidenceDecodeFailureAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-finding-evidence-decode", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Evidence decode client")
        self.engagement = self.store.create_engagement(
            self.operator,
            client.client_id,
            "Evidence decode engagement",
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Evidence decode finding",
            severity=Severity.LOW,
            asset="asset://decode-lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=("evidence:decode",),
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

    def _read(self):
        return self.store.list_findings(
            self.operator,
            engagement_id=self.engagement.engagement_id,
        )

    def test_decoder_edge_failures_share_evidence_integrity_error(self) -> None:
        cases = (
            ("invalid-json", '["evidence:decode"'),
            ("null", "null"),
            ("integer", "7"),
        )

        for case_name, raw in cases:
            with self.subTest(case=case_name):
                self._replace_evidence_json(raw)
                before = self._raw_evidence_json()

                with self.assertRaisesRegex(ValueError, "evidence"):
                    self._read()

                self.assertEqual(self._raw_evidence_json(), before)


if __name__ == "__main__":
    unittest.main()
