"""#808: real SQLite risk-approval tenant-lineage acceptance, offline only.

This module is intentionally tests-only. Expected failures capture the
unrepaired source-owner contract; they are not permission to deploy.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import (
    AccessContext,
    DomainStore,
    Role,
    TenantIsolationError,
)
from lightup.engagements import RiskLevel


class RiskApprovalTenantLineageSQLiteAcceptance(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="lightup-808-")
        self.addCleanup(self._tmp.cleanup)
        self.store = DomainStore(Path(self._tmp.name) / "scope-808.sqlite")
        self.operator = AccessContext("offline-operator", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "synthetic-tenant-a")
        self.client_b = self.store.create_client(self.operator, "synthetic-tenant-b")
        self.ctx_a = AccessContext("offline-a", Role.CLIENT_MEMBER, self.client_a.client_id)
        self.ctx_b = AccessContext("offline-b", Role.CLIENT_MEMBER, self.client_b.client_id)
        self.engagement_a = self.store.create_engagement(
            self.operator, self.client_a.client_id, "a-only-lab-engagement"
        )
        self.engagement_b = self.store.create_engagement(
            self.operator, self.client_b.client_id, "b-only-lab-engagement"
        )
        self.approval_a = self.store.request_risk_elevation(
            self.ctx_a,
            self.engagement_a.engagement_id,
            RiskLevel.ELEVATED,
            "synthetic a-only step-up request",
        )
        self.approval_b = self.store.request_risk_elevation(
            self.ctx_b,
            self.engagement_b.engagement_id,
            RiskLevel.STANDARD,
            "synthetic b-only step-up request",
        )

    def _ids(self, ctx, engagement_id=None):
        return {
            record.approval_id
            for record in self.store.list_risk_approvals(ctx, engagement_id)
        }

    def _row_snapshot(self):
        with sqlite3.connect(self.store.path) as con:
            return con.execute(
                "SELECT approval_id,client_id,engagement_id,requested_risk,"
                "justification,status,requested_by,created_at,decided_by,decided_at "
                "FROM risk_approvals ORDER BY approval_id"
            ).fetchall()

    def _corrupt_a_tenant_to_b(self):
        # This is a disposable SQLite fixture, not a product or client write.
        with sqlite3.connect(self.store.path) as con:
            updated = con.execute(
                "UPDATE risk_approvals SET client_id=? WHERE approval_id=?",
                (self.client_b.client_id, self.approval_a.approval_id),
            ).rowcount
        self.assertEqual(updated, 1)

    def test_canonical_owner_and_foreign_client_lists_are_isolated(self):
        self.assertEqual(self._ids(self.ctx_a), {self.approval_a.approval_id})
        self.assertEqual(self._ids(self.ctx_b), {self.approval_b.approval_id})

    def test_canonical_explicit_engagement_listing_is_scoped(self):
        self.assertEqual(
            self._ids(self.ctx_a, self.engagement_a.engagement_id),
            {self.approval_a.approval_id},
        )
        self.assertEqual(
            self._ids(self.ctx_b, self.engagement_b.engagement_id),
            {self.approval_b.approval_id},
        )

    def test_cross_client_explicit_engagement_read_denied_before_result(self):
        with self.assertRaises(TenantIsolationError):
            self.store.list_risk_approvals(
                self.ctx_b, self.engagement_a.engagement_id
            )
        with self.assertRaises(TenantIsolationError):
            self.store.list_risk_approvals(
                self.ctx_a, self.engagement_b.engagement_id
            )

    def test_operator_wide_audit_visibility_is_separate_from_client_contract(self):
        self.assertEqual(
            self._ids(self.operator),
            {self.approval_a.approval_id, self.approval_b.approval_id},
        )

    def test_canonical_lists_do_not_mutate_persisted_approval_rows(self):
        before = self._row_snapshot()
        self._ids(self.ctx_a)
        self._ids(self.ctx_b, self.engagement_b.engagement_id)
        self.assertEqual(self._row_snapshot(), before)

    @unittest.expectedFailure
    def test_red_foreign_client_cannot_read_relabelled_approval(self):
        # Original engagement belongs to A, despite B in the redundant column.
        self._corrupt_a_tenant_to_b()
        self.assertNotIn(self.approval_a.approval_id, self._ids(self.ctx_b))

    @unittest.expectedFailure
    def test_red_owner_cannot_read_approval_with_incoherent_client_lineage(self):
        self._corrupt_a_tenant_to_b()
        self.assertNotIn(
            self.approval_a.approval_id,
            self._ids(self.ctx_a, self.engagement_a.engagement_id),
        )

    @unittest.expectedFailure
    def test_red_corrupt_row_is_omitted_without_hiding_valid_b_approval(self):
        self._corrupt_a_tenant_to_b()
        self.assertEqual(self._ids(self.ctx_b), {self.approval_b.approval_id})

    def test_cross_tenant_explicit_read_remains_denied_after_corruption(self):
        self._corrupt_a_tenant_to_b()
        with self.assertRaises(TenantIsolationError):
            self.store.list_risk_approvals(
                self.ctx_b, self.engagement_a.engagement_id
            )

    def test_failed_explicit_read_and_listing_are_read_only(self):
        self._corrupt_a_tenant_to_b()
        before = self._row_snapshot()
        self._ids(self.ctx_b)
        with self.assertRaises(TenantIsolationError):
            self.store.list_risk_approvals(
                self.ctx_b, self.engagement_a.engagement_id
            )
        self.assertEqual(self._row_snapshot(), before)


if __name__ == "__main__":
    unittest.main()
