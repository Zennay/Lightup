from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class FindingTenantLineageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")
        self.ctx_a = AccessContext(
            "user-a", Role.CLIENT_ADMIN, self.client_a.client_id
        )
        self.ctx_b = AccessContext(
            "user-b", Role.CLIENT_ADMIN, self.client_b.client_id
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Q4"
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            "Weak TLS",
            Severity.MEDIUM,
            "app.acme.example",
            "Downgrade possible",
            "Enable TLS 1.2+ only",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _row(self) -> dict[str, object]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT * FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return dict(row)

    def _corrupt_client_lineage(self) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET client_id=? WHERE finding_id=?",
                (self.client_b.client_id, self.finding.finding_id),
            )

    def _orphan_engagement_lineage(self) -> None:
        with sqlite3.connect(self.store.path) as con:
            con.execute("PRAGMA foreign_keys=OFF")
            con.execute(
                "UPDATE findings SET engagement_id=? WHERE finding_id=?",
                ("missing-engagement", self.finding.finding_id),
            )

    def test_orphaned_finding_is_hidden_from_client_reads(self) -> None:
        self._orphan_engagement_lineage()
        before = self._row()

        self.assertEqual(self.store.list_findings(self.ctx_a), [])

        self.assertEqual(self._row(), before)

    def test_canonical_finding_remains_tenant_scoped(self) -> None:
        self.assertEqual(
            [item.finding_id for item in self.store.list_findings(self.ctx_a)],
            [self.finding.finding_id],
        )
        self.assertEqual(self.store.list_findings(self.ctx_b), [])

    def test_generic_client_read_revalidates_engagement_owner(self) -> None:
        self._corrupt_client_lineage()
        before = self._row()

        self.assertEqual(self.store.list_findings(self.ctx_b), [])
        self.assertEqual(
            self.store.list_findings(
                self.ctx_b, client_id=self.client_b.client_id
            ),
            [],
        )

        self.assertEqual(self._row(), before)

    def test_explicit_engagement_read_filters_incoherent_client_id(self) -> None:
        self._corrupt_client_lineage()
        before = self._row()

        self.assertEqual(
            self.store.list_findings(
                self.ctx_a, engagement_id=self.engagement.engagement_id
            ),
            [],
        )

        self.assertEqual(self._row(), before)

    def test_operator_wide_audit_visibility_is_unchanged(self) -> None:
        self._corrupt_client_lineage()

        visible = self.store.list_findings(self.operator)

        self.assertEqual(
            [item.finding_id for item in visible],
            [self.finding.finding_id],
        )


if __name__ == "__main__":
    unittest.main()
