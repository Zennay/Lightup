"""Isolated real-DomainStore opt-in checked tenant CSV tests (no real users)."""
from __future__ import annotations

import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.domain import (
    AccessContext,
    DomainStore,
    Role,
    TenantIsolationError,
)
from lightup.finding_export_service import render_client_findings_csv
from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.models import Severity


class TenantCheckedUnicodeCsvTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = DomainStore(Path(temp.name) / "test.sqlite")
        self.operator = AccessContext("trusted-synthetic-op", Role.OPERATOR)
        self.a = self.store.create_client(self.operator, "Client A synthetic")
        self.b = self.store.create_client(self.operator, "Client B synthetic")
        self.ctx_a = AccessContext("trusted-synthetic-a", Role.CLIENT_ADMIN, self.a.client_id)
        self.ctx_b = AccessContext("trusted-synthetic-b", Role.CLIENT_MEMBER, self.b.client_id)
        self.eng_a = self.store.create_engagement(
            self.operator, self.a.client_id, "Synthetic engagement A"
        )
        self.eng_a2 = self.store.create_engagement(
            self.operator, self.a.client_id, "Synthetic engagement A2"
        )
        self.eng_b = self.store.create_engagement(
            self.operator, self.b.client_id, "Synthetic engagement B"
        )

    def record(self, eng, title, remediation="Document patch"):
        return self.store.record_finding(
            self.operator, eng.engagement_id, title,
            Severity.LOW, "synthetic-target.invalid", "test-only impact",
            remediation, ("private-synthetic-evidence-id",)
        )

    def rows(self, ctx=None, client=None, **kwargs):
        raw = render_tenant_findings_csv_checked(
            self.store,
            self.ctx_a if ctx is None else ctx,
            self.a.client_id if client is None else client,
            **kwargs,
        )
        return raw, list(csv.DictReader(io.StringIO(raw)))

    def persisted(self):
        with self.store._connect() as con:
            return tuple(tuple(row) for row in con.execute(
                "SELECT finding_id,client_id,engagement_id,title,asset,"
                "remediation,retest_status,evidence_ids_json FROM findings "
                "ORDER BY finding_id"
            ))

    def test_authorized_same_tenant_good_international_text_and_no_raw_data(self):
        f1 = self.record(self.eng_a, "Herstel voor Zaak Étude", "Corrigeer instellingen")
        f2 = self.record(self.eng_a2, "Clean λ report", "Retest na patch")
        self.record(self.eng_b, "Cross tenant secret title")
        before = self.persisted()
        raw, rows = self.rows()
        self.assertEqual({r["finding_id"] for r in rows}, {f1.finding_id, f2.finding_id})
        self.assertIn("Zaak Étude", raw)
        self.assertIn("λ", raw)
        self.assertNotIn("Cross tenant secret", raw)
        self.assertNotIn("private-synthetic-evidence-id", raw)
        self.assertNotIn("synthetic-target.invalid", raw)
        self.assertEqual(self.persisted(), before)

    def test_operator_explicit_engagement_only(self):
        one = self.record(self.eng_a, "A only")
        self.record(self.eng_a2, "A2 only")
        self.record(self.eng_b, "B only")
        _, rows = self.rows(
            ctx=self.operator, engagement_id=self.eng_a.engagement_id
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_id"], one.finding_id)
        self.assertEqual(self.rows(ctx=self.operator, client=self.b.client_id)[1][0]["title"], "B only")

    def test_ascii_formula_still_escaped_by_existing_renderer(self):
        self.record(self.eng_a, "=1+1", "@run formula")
        _, rows = self.rows()
        self.assertEqual(rows[0]["title"], "'=1+1")
        self.assertEqual(rows[0]["remediation"], "'@run formula")

    def test_unicode_obfuscated_formula_fails_whole_tenant_batch(self):
        self.record(self.eng_a, "good canonical finding")
        self.record(self.eng_a2, "\u200b=SUM(1)")
        before = self.persisted()
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaises(ValueError):
                render_tenant_findings_csv_checked(
                    self.store, self.ctx_a, self.a.client_id
                )
            serializer.assert_not_called()
        self.assertEqual(self.persisted(), before)

    def test_unicode_compatibility_prefix_in_remediation_denied(self):
        self.record(self.eng_a, "good title", "\uff1dSUM(1)")
        with self.assertRaises(ValueError):
            self.rows()

    def test_default_producer_does_not_yet_apply_optin_guard(self):
        finding = self.record(self.eng_a, "\u200b=SUM(1)")
        default = render_client_findings_csv(
            self.store, self.ctx_a, self.a.client_id
        )
        rows = list(csv.DictReader(io.StringIO(default)))
        self.assertEqual(rows[0]["finding_id"], finding.finding_id)
        self.assertEqual(rows[0]["title"], "\u200b=SUM(1)")
        with self.assertRaises(ValueError):
            self.rows()

    def test_cross_tenant_and_wrong_engagement_rejected_before_export(self):
        self.record(self.eng_a, "A good")
        self.record(self.eng_b, "B good")
        before = self.persisted()
        for ctx, target in (
            (self.ctx_a, self.b.client_id),
            (self.ctx_b, self.a.client_id),
        ):
            with self.subTest(target=target):
                with self.assertRaises(TenantIsolationError):
                    self.rows(ctx=ctx, client=target)
        with self.assertRaises((TenantIsolationError, KeyError)):
            self.rows(engagement_id=self.eng_b.engagement_id)
        self.assertEqual(self.persisted(), before)

    def test_missing_context_or_fake_domain_object_refused(self):
        self.record(self.eng_a, "A good")
        for store, ctx in (
            (object(), self.ctx_a),
            (self.store, object()),
            (self.store, None),
        ):
            with self.subTest(store=type(store), ctx=type(ctx)):
                with self.assertRaises(ValueError):
                    render_tenant_findings_csv_checked(store, ctx, self.a.client_id)

    def test_forged_access_context_subclass_refused(self):
        class SubContext(AccessContext):
            pass
        self.record(self.eng_a, "A good")
        fake = SubContext(self.ctx_a.user_id, self.ctx_a.role, self.ctx_a.client_id)
        with self.assertRaises(ValueError):
            self.rows(ctx=fake)

    def test_whitespace_and_noncanonical_client_ids_fail_closed(self):
        self.record(self.eng_a, "A good")
        for bad in ("", " ", " " + self.a.client_id, self.a.client_id + " ", None, 22):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    render_tenant_findings_csv_checked(self.store, self.ctx_a, bad)

    def test_invalid_legacy_stored_enum_fails_before_output(self):
        f = self.record(self.eng_a, "Source good")
        before = self.persisted()
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET severity=? WHERE finding_id=?",
                ("a-future-unknown-severity", f.finding_id)
            )
        with self.assertRaises(ValueError):
            self.rows()
        self.assertNotEqual(self.persisted(), before)

    def test_oversized_unicode_field_fails_without_serializer(self):
        self.record(self.eng_a, "É" * 5000)
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaises(ValueError):
                self.rows()
            serializer.assert_not_called()

    def test_empty_authorized_tenant_still_header_only(self):
        raw, rows = self.rows()
        self.assertEqual(rows, [])
        self.assertEqual(raw.split("\r\n")[0],
                         '"finding_id","title","severity","retest_status","remediation"')


if __name__ == "__main__":
    unittest.main()
