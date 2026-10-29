import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.finding_export_service import render_client_findings_csv
from lightup.models import RetestStatus, Severity


class TenantFindingCsvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.op = AccessContext("operator", Role.OPERATOR)
        self.a = self.store.create_client(self.op, "Tenant A")
        self.b = self.store.create_client(self.op, "Tenant B")
        self.ctx_a = AccessContext("user-a", Role.CLIENT_ADMIN, self.a.client_id)
        self.ctx_b = AccessContext("user-b", Role.CLIENT_MEMBER, self.b.client_id)
        self.eng_a = self.store.create_engagement(self.op, self.a.client_id, "A first")
        self.eng_a2 = self.store.create_engagement(self.op, self.a.client_id, "A second")
        self.eng_b = self.store.create_engagement(self.op, self.b.client_id, "B first")
        self.fa = self.finding(self.eng_a, "=A finding")
        self.fa2 = self.finding(self.eng_a2, "A second finding")
        self.fb = self.finding(self.eng_b, "B private finding")

    def tearDown(self):
        self.tmp.cleanup()

    def finding(self, engagement, title):
        return self.store.record_finding(
            self.op, engagement.engagement_id, title, Severity.HIGH,
            "private-target.invalid", "private-impact",
            "password=canary-secret", ("private-evidence-id",))

    def snapshot(self):
        with self.store._connect() as con:
            return {table: [tuple(row) for row in con.execute(f"SELECT * FROM {table} ORDER BY 1")]
                    for table in ("clients", "engagements", "findings")}

    def rows(self, ctx, client_id, **kwargs):
        return list(csv.DictReader(io.StringIO(
            render_client_findings_csv(self.store, ctx, client_id, **kwargs))))

    def test_client_export_is_scoped_and_guarded(self):
        before = self.snapshot()
        rows = self.rows(self.ctx_a, self.a.client_id)
        self.assertEqual({row["finding_id"] for row in rows},
                         {self.fa.finding_id, self.fa2.finding_id})
        first = next(row for row in rows if row["finding_id"] == self.fa.finding_id)
        self.assertEqual(first["title"], "'=A finding")
        self.assertEqual(first["remediation"], "password=[REDACTED]")
        self.assertEqual(before, self.snapshot())

    def test_operator_must_select_one_client(self):
        rows = self.rows(self.op, self.a.client_id)
        self.assertNotIn(self.fb.finding_id, [row["finding_id"] for row in rows])
        with self.assertRaises(ValueError):
            render_client_findings_csv(self.store, self.op, None)

    def test_client_member_can_export_only_own_findings(self):
        self.assertEqual(self.rows(self.ctx_b, self.b.client_id)[0]["finding_id"],
                         self.fb.finding_id)
        before = self.snapshot()
        with self.assertRaises(TenantIsolationError):
            self.rows(self.ctx_b, self.a.client_id)
        self.assertEqual(before, self.snapshot())

    def test_engagement_filter_is_exact(self):
        rows = self.rows(self.ctx_a, self.a.client_id,
                         engagement_id=self.eng_a2.engagement_id)
        self.assertEqual([row["finding_id"] for row in rows], [self.fa2.finding_id])

    def test_operator_client_engagement_mismatch_fails_before_findings_read(self):
        with patch.object(self.store, "list_findings") as read:
            with self.assertRaises(TenantIsolationError):
                self.rows(self.op, self.a.client_id,
                          engagement_id=self.eng_b.engagement_id)
            read.assert_not_called()

    def test_cross_tenant_engagement_filter_fails(self):
        with self.assertRaises(TenantIsolationError):
            self.rows(self.ctx_a, self.a.client_id,
                      engagement_id=self.eng_b.engagement_id)

    def test_corrupt_duplicate_tenant_does_not_leak_generic_export(self):
        with self.store._connect() as con:
            con.execute("UPDATE findings SET client_id=? WHERE finding_id=?",
                        (self.a.client_id, self.fb.finding_id))
        before = self.snapshot()
        for ctx in (self.ctx_a, self.op):
            with self.subTest(role=ctx.role):
                with self.assertRaises(TenantIsolationError):
                    self.rows(ctx, self.a.client_id)
        self.assertEqual(before, self.snapshot())

    def test_corrupt_duplicate_tenant_does_not_leak_engagement_export(self):
        with self.store._connect() as con:
            con.execute("UPDATE findings SET client_id=? WHERE finding_id=?",
                        (self.b.client_id, self.fa.finding_id))
        before = self.snapshot()
        for ctx in (self.ctx_a, self.op):
            with self.subTest(role=ctx.role):
                with self.assertRaises(TenantIsolationError):
                    self.rows(ctx, self.a.client_id,
                              engagement_id=self.eng_a.engagement_id)
        self.assertEqual(before, self.snapshot())

    def test_orphaned_findings_fail_closed_without_repair(self):
        with self.store._connect() as con:
            con.execute("PRAGMA foreign_keys=OFF")
            con.execute("DELETE FROM engagements WHERE engagement_id=?",
                        (self.eng_a.engagement_id,))
        before = self.snapshot()
        with self.assertRaises(KeyError):
            self.rows(self.op, self.a.client_id)
        self.assertEqual(before, self.snapshot())

    def test_unknown_client_and_engagement_fail_closed(self):
        with self.assertRaises(KeyError):
            self.rows(self.op, "missing-client")
        with self.assertRaises(KeyError):
            self.rows(self.ctx_a, self.a.client_id, engagement_id="missing-engagement")

    def test_invalid_identity_inputs_do_not_query_findings(self):
        class TextChild(str):
            pass
        for value in ("", "  ", None, 7, " leading", TextChild(self.a.client_id)):
            with self.subTest(value=repr(value)):
                with patch.object(self.store, "list_findings") as read:
                    with self.assertRaises(ValueError):
                        self.rows(self.op, value)
                    read.assert_not_called()
        with self.assertRaises(ValueError):
            render_client_findings_csv(self.store, object(), self.a.client_id)

    def test_empty_existing_tenant_has_header_only(self):
        empty = self.store.create_client(self.op, "Empty")
        self.assertEqual(self.rows(self.op, empty.client_id), [])

    def test_source_payloads_and_targets_are_omitted(self):
        output = render_client_findings_csv(self.store, self.ctx_a, self.a.client_id)
        for value in ("private-target.invalid", "private-impact", "private-evidence-id",
                      "canary-secret", "B private finding"):
            self.assertNotIn(value, output)

    def test_retest_status_survives_export_without_mutation(self):
        self.store.set_retest_status(self.op, self.fa.finding_id, RetestStatus.FIXED)
        before = self.snapshot()
        row = self.rows(self.ctx_a, self.a.client_id,
                        engagement_id=self.eng_a.engagement_id)[0]
        self.assertEqual(row["retest_status"], "fixed")
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
