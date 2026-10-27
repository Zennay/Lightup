"""Disposable real-DomainStore checks for Unicode CSV source-level gap.

The opt-in guard remains intentionally *unwired* to the authenticated service.
These tests do not use real customer records or spreadsheet clients.
"""
from __future__ import annotations

import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.finding_export_service import render_client_findings_csv
from lightup.finding_export_unicode_integrity import render_findings_csv_checked
from lightup.models import Finding, Severity


class TenantUnicodeCsvProducerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "synthetic.sqlite")
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Synthetic A")
        self.client_b = self.store.create_client(self.operator, "Synthetic B")
        self.a_context = AccessContext("synthetic-a", Role.CLIENT_ADMIN, self.client_a.client_id)
        self.b_context = AccessContext("synthetic-b", Role.CLIENT_MEMBER, self.client_b.client_id)
        self.eng_a = self.store.create_engagement(self.operator, self.client_a.client_id, "Lab A")
        self.eng_b = self.store.create_engagement(self.operator, self.client_b.client_id, "Lab B")
        self.ambiguous_title = "\u200b=SUM(1)"
        self.record_a = self.store.record_finding(
            self.operator, self.eng_a.engagement_id, self.ambiguous_title,
            Severity.LOW, "synthetic-a.invalid", "synthetic-impact",
            "Document CSP", ("synthetic-a-evidence",))
        self.record_b = self.store.record_finding(
            self.operator, self.eng_b.engagement_id, "Normal B finding",
            Severity.HIGH, "synthetic-b.invalid", "synthetic-impact",
            "Document patch", ("synthetic-b-evidence",))

    def database_snapshot(self):
        with self.store._connect() as db:
            return tuple(tuple(r) for r in db.execute(
                "SELECT finding_id, client_id, engagement_id, title, remediation, "
                "retest_status, evidence_ids_json FROM findings ORDER BY finding_id"))

    def read(self, ctx, client_id, **kwargs):
        return render_client_findings_csv(self.store, ctx, client_id, **kwargs)

    def test_current_authorized_tenant_service_preserves_invisible_prefix(self):
        before = self.database_snapshot()
        result = self.read(self.a_context, self.client_a.client_id)
        rows = list(csv.DictReader(io.StringIO(result)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_id"], self.record_a.finding_id)
        self.assertEqual(rows[0]["title"], self.ambiguous_title)
        self.assertNotIn(self.record_b.finding_id, result)
        self.assertNotIn("synthetic-a-evidence", result)
        self.assertNotIn("synthetic-a.invalid", result)
        self.assertEqual(before, self.database_snapshot())

    def test_default_engagement_filter_and_operator_selection_also_unchecked(self):
        a = self.read(self.operator, self.client_a.client_id,
                      engagement_id=self.eng_a.engagement_id)
        self.assertEqual(list(csv.DictReader(io.StringIO(a)))[0]["title"],
                         self.ambiguous_title)
        b = self.read(self.operator, self.client_b.client_id)
        self.assertNotIn(self.ambiguous_title, b)

    def test_client_context_does_not_gain_cross_tenant_export(self):
        before = self.database_snapshot()
        with self.assertRaises(TenantIsolationError):
            self.read(self.b_context, self.client_a.client_id)
        with self.assertRaises(TenantIsolationError):
            self.read(self.a_context, self.client_b.client_id)
        self.assertEqual(before, self.database_snapshot())

    def test_optin_projection_rejects_real_persisted_finding_before_renderer(self):
        before = self.database_snapshot()
        f = self.record_a
        projection = Finding(
            finding_id=f.finding_id, title=f.title, severity=f.severity,
            target=f.asset, remediation=f.remediation, retest_status=f.retest_status,
        )
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
            with self.assertRaises(ValueError):
                render_findings_csv_checked([projection])
            render.assert_not_called()
        self.assertEqual(before, self.database_snapshot())


if __name__ == "__main__":
    unittest.main()
