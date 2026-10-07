from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel


class RiskApprovalTenantLineageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-owner", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")
        self.ctx_a = AccessContext(
            "admin-a",
            Role.CLIENT_ADMIN,
            self.client_a.client_id,
        )
        self.ctx_b = AccessContext(
            "admin-b",
            Role.CLIENT_ADMIN,
            self.client_b.client_id,
        )
        self.engagement_a = self.store.create_engagement(
            self.operator,
            self.client_a.client_id,
            "Acme risk review",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _new_approval(self):
        return self.store.request_risk_elevation(
            self.ctx_a,
            self.engagement_a.engagement_id,
            RiskLevel.ELEVATED,
            "Acme elevation request",
        )

    def test_canonical_risk_approval_is_visible_only_to_owning_client(self) -> None:
        approval = self._new_approval()

        self.assertEqual(
            [record.approval_id for record in self.store.list_risk_approvals(self.ctx_a)],
            [approval.approval_id],
        )
        self.assertEqual(self.store.list_risk_approvals(self.ctx_b), [])

    def test_explicit_engagement_read_rejects_mismatched_client_lineage(self) -> None:
        approval = self._new_approval()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET client_id=? WHERE approval_id=?",
                (self.client_b.client_id, approval.approval_id),
            )

        self.assertEqual(
            self.store.list_risk_approvals(
                self.ctx_a,
                self.engagement_a.engagement_id,
            ),
            [],
        )

    def test_corrupt_denormalized_client_id_cannot_cross_tenant_boundary(self) -> None:
        approval = self._new_approval()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET client_id=? WHERE approval_id=?",
                (self.client_b.client_id, approval.approval_id),
            )

        # The engagement still belongs to client A. A forged/drifted duplicated
        # client_id must not make that approval visible to client B.
        self.assertEqual(self.store.list_risk_approvals(self.ctx_b), [])

        # The read guard must be non-mutating: repair/audit policy is separate.
        with self.store._connect() as con:
            row = con.execute(
                "SELECT client_id, engagement_id FROM risk_approvals "
                "WHERE approval_id=?",
                (approval.approval_id,),
            ).fetchone()
        self.assertEqual(row["client_id"], self.client_b.client_id)
        self.assertEqual(row["engagement_id"], self.engagement_a.engagement_id)


if __name__ == "__main__":
    unittest.main()
