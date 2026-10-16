from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, ApprovalStatus, DomainStore, Role
from lightup.engagements import RiskLevel


class RiskDecisionAuditCoherenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-owner", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_ctx = AccessContext(
            "client-admin",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Risk audit coherence",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _new_approval(self):
        return self.store.request_risk_elevation(
            self.client_ctx,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            "requires a second operator",
        )

    def _row(self, approval_id: str):
        with self.store._connect() as con:
            return con.execute(
                "SELECT status, decided_by, decided_at "
                "FROM risk_approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()

    def _assert_pending_audit_preserved(
        self,
        approval_id: str,
        decided_by: str | None,
        decided_at: str | None,
    ) -> None:
        row = self._row(approval_id)
        self.assertEqual(row["status"], ApprovalStatus.PENDING.value)
        self.assertEqual(row["decided_by"], decided_by)
        self.assertEqual(row["decided_at"], decided_at)

    def test_untouched_pending_approval_remains_decidable(self) -> None:
        approval = self._new_approval()
        reviewer = AccessContext("op-reviewer", Role.OPERATOR)

        decided = self.store.decide_risk_elevation(
            reviewer,
            approval.approval_id,
            True,
        )

        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.decided_by, reviewer.user_id)
        self.assertIsNotNone(decided.decided_at)

    def test_pending_row_with_decided_by_fails_closed_before_mutation(self) -> None:
        approval = self._new_approval()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET decided_by=? WHERE approval_id=?",
                ("legacy-reviewer", approval.approval_id),
            )

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                AccessContext("op-reviewer", Role.OPERATOR),
                approval.approval_id,
                True,
            )

        self._assert_pending_audit_preserved(
            approval.approval_id,
            "legacy-reviewer",
            None,
        )

    def test_pending_row_with_decided_at_fails_closed_before_mutation(self) -> None:
        approval = self._new_approval()
        decided_at = "2026-10-07T15:30:00+00:00"
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET decided_at=? WHERE approval_id=?",
                (decided_at, approval.approval_id),
            )

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                AccessContext("op-reviewer", Role.OPERATOR),
                approval.approval_id,
                False,
            )

        self._assert_pending_audit_preserved(
            approval.approval_id,
            None,
            decided_at,
        )

    def test_pending_row_with_complete_stale_audit_fails_closed(self) -> None:
        approval = self._new_approval()
        decided_at = "2026-10-07T15:31:00+00:00"
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET decided_by=?, decided_at=? "
                "WHERE approval_id=?",
                ("legacy-reviewer", decided_at, approval.approval_id),
            )

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                AccessContext("op-new-reviewer", Role.OPERATOR),
                approval.approval_id,
                True,
            )

        self._assert_pending_audit_preserved(
            approval.approval_id,
            "legacy-reviewer",
            decided_at,
        )


if __name__ == "__main__":
    unittest.main()
