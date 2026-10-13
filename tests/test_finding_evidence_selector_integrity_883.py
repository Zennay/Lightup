"""#883: independent real-SQLite evidence rejection across finding read selectors.

Expected-failure cases are *unresolved source-owner RED*, not security PASS.
No production files, real clients, targets, providers, or scanning used.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class FindingEvidenceSelectorIntegrityAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "selectors.db"
        self.store = DomainStore(self.db_path)
        self.op = AccessContext("synthetic-op", Role.OPERATOR)
        tenant_a = self.store.create_client(self.op, "Selector tenant A")
        tenant_b = self.store.create_client(self.op, "Selector tenant B")
        self.a = AccessContext("synthetic-a", Role.CLIENT_ADMIN, tenant_a.client_id)
        self.b = AccessContext("synthetic-b", Role.CLIENT_ADMIN, tenant_b.client_id)
        engagement_a = self.store.create_engagement(self.op, tenant_a.client_id, "Synthetic A")
        engagement_b = self.store.create_engagement(self.op, tenant_b.client_id, "Synthetic B")
        self.engagement_id = engagement_a.engagement_id
        self.finding = self._finding(engagement_a.engagement_id, "A", ("ev:a-1", "ev:a-2"))
        self.other_finding = self._finding(engagement_b.engagement_id, "B", ("ev:b",))

    def _finding(self, engagement_id: str, title: str, refs: tuple[str, ...]):
        return self.store.record_finding(
            self.op,
            engagement_id,
            title,
            Severity.LOW,
            f"asset://{title}",
            "Offline synthetic impact",
            "Offline synthetic remediation",
            evidence_ids=refs,
        )

    def _read_raw(self) -> str:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    def _replace_raw(self, raw: str) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )
        self.assertEqual(self._read_raw(), raw)

    def _select(self, selector: str):
        if selector == "engagement":
            return self.store.list_findings(self.op, engagement_id=self.engagement_id)
        if selector == "tenant":
            return self.store.list_findings(self.a)
        if selector == "operator":
            return self.store.list_findings(self.op)
        raise AssertionError(f"invalid fixture selector {selector}")

    def _require_reject_unchanged(self, selector: str, raw: str) -> None:
        self._replace_raw(raw)
        before = self._read_raw()
        try:
            with self.assertRaisesRegex(ValueError, "[Ee]vidence"):
                self._select(selector)
        finally:
            self.assertEqual(self._read_raw(), before)
            surviving = self.store.list_findings(self.b)
            self.assertEqual(len(surviving), 1)
            self.assertEqual(surviving[0].finding_id, self.other_finding.finding_id)
            self.assertEqual(surviving[0].evidence_ids, ("ev:b",))

    def test_engagement_selector_canonical_evidence(self) -> None:
        rows = self._select("engagement")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].evidence_ids, ("ev:a-1", "ev:a-2"))

    def test_tenant_selector_canonical_evidence(self) -> None:
        rows = self._select("tenant")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].finding_id, self.finding.finding_id)
        self.assertEqual(rows[0].evidence_ids, ("ev:a-1", "ev:a-2"))

    def test_operator_audit_selector_preserves_both_tenants(self) -> None:
        rows = self._select("operator")
        self.assertEqual(
            {row.finding_id: row.evidence_ids for row in rows},
            {
                self.finding.finding_id: ("ev:a-1", "ev:a-2"),
                self.other_finding.finding_id: ("ev:b",),
            },
        )

    @unittest.expectedFailure  # #856 pending owner fix
    def test_engagement_rejects_string(self) -> None:
        self._require_reject_unchanged("engagement", '"ev:a-1"')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_tenant_rejects_string(self) -> None:
        self._require_reject_unchanged("tenant", '"ev:a-1"')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_operator_rejects_string(self) -> None:
        self._require_reject_unchanged("operator", '"ev:a-1"')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_engagement_rejects_non_string_array_item(self) -> None:
        self._require_reject_unchanged("engagement", '["ev:a-1", 17]')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_tenant_rejects_non_string_array_item(self) -> None:
        self._require_reject_unchanged("tenant", '["ev:a-1", 17]')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_operator_rejects_non_string_array_item(self) -> None:
        self._require_reject_unchanged("operator", '["ev:a-1", 17]')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_engagement_rejects_duplicate_array(self) -> None:
        self._require_reject_unchanged("engagement", '["ev:a-1", "ev:a-1"]')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_tenant_rejects_duplicate_array(self) -> None:
        self._require_reject_unchanged("tenant", '["ev:a-1", "ev:a-1"]')

    @unittest.expectedFailure  # #856 pending owner fix
    def test_operator_rejects_duplicate_array(self) -> None:
        self._require_reject_unchanged("operator", '["ev:a-1", "ev:a-1"]')


if __name__ == "__main__":
    unittest.main()
