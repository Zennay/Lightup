from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, ApprovalStatus, DomainStore, Role, RoleError
from lightup.engagements import RiskLevel


class RiskRequesterProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-root", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Requester provenance boundary"
        )
        self.requester = AccessContext("op-reviewer", Role.OPERATOR)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _pending(self):
        return self.store.request_risk_elevation(
            self.requester,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            "requester provenance must stay canonical",
        )

    def _persisted_row(self, approval_id: str):
        with self.store._connect() as con:
            return con.execute(
                "SELECT * FROM risk_approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()

    def test_blob_requester_provenance_cannot_bypass_self_approval(self) -> None:
        approval = self._pending()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET requested_by=? WHERE approval_id=?",
                (
                    sqlite3.Binary(self.requester.user_id.encode("utf-8")),
                    approval.approval_id,
                ),
            )

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                self.requester, approval.approval_id, True
            )

        row = self._persisted_row(approval.approval_id)
        self.assertEqual(row["status"], ApprovalStatus.PENDING.value)
        self.assertIsNone(row["decided_by"])
        self.assertIsNone(row["decided_at"])

    def test_blank_requester_provenance_fails_closed_without_mutation(self) -> None:
        for corrupted in ("", "   "):
            with self.subTest(corrupted=corrupted):
                approval = self._pending()
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE risk_approvals SET requested_by=? WHERE approval_id=?",
                        (corrupted, approval.approval_id),
                    )

                with self.assertRaises(ValueError):
                    self.store.decide_risk_elevation(
                        AccessContext("op-independent", Role.OPERATOR),
                        approval.approval_id,
                        False,
                    )

                row = self._persisted_row(approval.approval_id)
                self.assertEqual(row["status"], ApprovalStatus.PENDING.value)
                self.assertIsNone(row["decided_by"])
                self.assertIsNone(row["decided_at"])

    def test_canonical_requester_provenance_preserves_decision_controls(self) -> None:
        approval = self._pending()

        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(
                self.requester, approval.approval_id, True
            )

        reviewer = AccessContext("op-independent", Role.OPERATOR)
        decided = self.store.decide_risk_elevation(
            reviewer, approval.approval_id, True
        )
        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.decided_by, reviewer.user_id)


if __name__ == "__main__":
    unittest.main()
