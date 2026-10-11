"""Independent W4 postrepair admission tests on the opt-in W3 tenant CSV.

All database and input tampering is in disposable synthetic SQLite only.
No default product route, real customer or target is exercised.
"""
from __future__ import annotations

from dataclasses import replace
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import (
    AccessContext, DomainStore, Role, TenantIsolationError,
)
from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.models import Severity


class TenantCsvPostrepairTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "local.sqlite")
        self.op = AccessContext("synthetic-operator", Role.OPERATOR)
        self.tenant = self.store.create_client(self.op, "Lab tenant")
        self.other = self.store.create_client(self.op, "Separate lab tenant")
        self.ctx = AccessContext("synthetic-tenant", Role.CLIENT_MEMBER, self.tenant.client_id)
        self.eng = self.store.create_engagement(self.op, self.tenant.client_id, "Engagement One")
        self.sibling = self.store.create_engagement(self.op, self.tenant.client_id, "Engagement Two")
        self.foreign = self.store.create_engagement(self.op, self.other.client_id, "Foreign")
    
    def finding(self, engagement=None, title="Synthetic finding"):
        eng = self.eng if engagement is None else engagement
        return self.store.record_finding(
            self.op, eng.engagement_id, title, Severity.MEDIUM,
            "synthetic.invalid", "local impact", "Patch/retest with approval",
            ("lab-only-evidence-reference",),
        )

    def export(self, **filters):
        return render_tenant_findings_csv_checked(
            self.store, self.ctx, self.tenant.client_id, **filters
        )

    def test_corrupt_selector_cross_tenant_row_is_rejected_before_projection(self):
        foreign = self.finding(self.foreign)
        with patch.object(self.store, "list_findings", return_value=[foreign]), patch(
            "lightup.finding_export_tenant_checked.render_findings_csv_checked"
        ) as serializer:
            with self.assertRaises(TenantIsolationError):
                self.export()
            serializer.assert_not_called()

    def test_corrupt_selector_wrong_engagement_is_rejected_before_projection(self):
        sibling = self.finding(self.sibling)
        with patch.object(self.store, "list_findings", return_value=[sibling]), patch(
            "lightup.finding_export_tenant_checked.render_findings_csv_checked"
        ) as serializer:
            with self.assertRaises(TenantIsolationError):
                self.export(engagement_id=self.eng.engagement_id)
            serializer.assert_not_called()

    def test_corrupt_selector_aliased_ownership_is_rejected(self):
        canonical = self.finding()
        wrong = replace(canonical, client_id=self.other.client_id)
        with patch.object(self.store, "list_findings", return_value=[wrong]):
            with self.assertRaises(TenantIsolationError):
                self.export()

    def test_unrendered_target_must_still_pass_unicode_integrity_gate(self):
        record = self.finding()
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET asset=? WHERE finding_id=?",
                ("\u200bsynthetic.invalid", record.finding_id),
            )
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as renderer:
            with self.assertRaises(ValueError):
                self.export()
            renderer.assert_not_called()

    def test_nfkc_equivalent_but_distinct_persisted_finding_ids_are_rejected(self):
        first = self.finding(title="First synthetic finding")
        second = self.finding(title="Second synthetic finding")
        equivalent_id = first.finding_id.replace("-", "\uff0d", 1)
        self.assertNotEqual(first.finding_id, equivalent_id)
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET finding_id=? WHERE finding_id=?",
                (equivalent_id, second.finding_id),
            )
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as renderer:
            with self.assertRaises(ValueError):
                self.export()
            renderer.assert_not_called()

    def test_129_synthetic_records_are_denied_before_serialization(self):
        for index in range(129):
            self.finding(title=f"Lab finding {index:03}")
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as renderer:
            with self.assertRaises(ValueError):
                self.export()
            renderer.assert_not_called()

    def test_request_cannot_reuse_an_old_safe_selection_after_source_changes(self):
        record = self.finding(title="Known safe")
        first = list(csv.DictReader(io.StringIO(self.export())))
        self.assertEqual(first[0]["title"], "Known safe")
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET title=? WHERE finding_id=?",
                ("\u200b=SUM(1)", record.finding_id),
            )
        with self.assertRaises(ValueError):
            self.export()
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET title=? WHERE finding_id=?",
                ("Corrected étude", record.finding_id),
            )
        later = list(csv.DictReader(io.StringIO(self.export())))
        self.assertEqual(later[0]["title"], "Corrected étude")

    def test_reject_unsupported_persisted_enumeration_without_partial_output(self):
        record = self.finding()
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET retest_status=? WHERE finding_id=?",
                ("unsupported_future_retest", record.finding_id),
            )
        with self.assertRaises(ValueError):
            self.export()


if __name__ == "__main__":
    unittest.main()
