from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import RetestStatus, Severity


class RetestStatusEvidenceAtomicityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-retest-evidence-atomicity", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Retest evidence atomicity client")
        self.engagement = self.store.create_engagement(
            self.operator,
            client.client_id,
            "Retest evidence atomicity engagement",
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Evidence-backed finding",
            severity=Severity.MEDIUM,
            asset="asset://lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=("evidence:one",),
        )

    def _raw_row(self) -> tuple[str, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT retest_status,evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["retest_status"], row["evidence_ids_json"]

    def _replace_evidence_json(self, raw: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def _assert_corrupt_rejected_without_mutation(self, raw: str) -> None:
        self._replace_evidence_json(raw)
        before = self._raw_row()

        with self.assertRaisesRegex(ValueError, "evidence"):
            self.store.set_retest_status(
                self.operator,
                self.finding.finding_id,
                RetestStatus.FIXED,
            )

        self.assertEqual(self._raw_row(), before)

    def test_canonical_finding_can_transition_retest_status(self) -> None:
        updated = self.store.set_retest_status(
            self.operator,
            self.finding.finding_id,
            RetestStatus.FIX_PENDING,
        )

        self.assertIs(updated.retest_status, RetestStatus.FIX_PENDING)
        self.assertEqual(
            self._raw_row(),
            (RetestStatus.FIX_PENDING.value, '["evidence:one"]'),
        )

    def test_string_shaped_evidence_rejects_without_partial_mutation(self) -> None:
        self._assert_corrupt_rejected_without_mutation('"evidence:one"')

    def test_null_evidence_rejects_without_partial_mutation(self) -> None:
        self._assert_corrupt_rejected_without_mutation("null")

    def test_invalid_json_rejects_without_partial_mutation(self) -> None:
        self._assert_corrupt_rejected_without_mutation('["evidence:one"')


if __name__ == "__main__":
    unittest.main()
