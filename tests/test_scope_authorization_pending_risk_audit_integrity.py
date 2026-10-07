from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, ApprovalStatus, DomainStore, Role
from lightup.engagements import RiskLevel


class PendingRiskApprovalAuditIntegrityTest(unittest.TestCase):
    """Acceptance contract for internally inconsistent PENDING risk approvals."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-owner", Role.OPERATOR)
        self.reviewer = AccessContext("op-reviewer", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_ctx = AccessContext(
            "client-requester", Role.CLIENT_ADMIN, self.client.client_id
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Pending audit integrity"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _request(self):
        return self.store.request_risk_elevation(
            self.client_ctx,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            "requires independent operator approval",
        )

    def _raw_decision_state(self, approval_id: str) -> tuple[str, str | None, str | None]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT status, decided_by, decided_at "
                "FROM risk_approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["status"], row["decided_by"], row["decided_at"]

    def test_pending_approval_with_decided_by_fails_closed_without_mutation(self) -> None:
        approval = self._request()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET decided_by=? WHERE approval_id=?",
                ("legacy-reviewer", approval.approval_id),
            )

        before = self._raw_decision_state(approval.approval_id)
        self.assertEqual(before, (ApprovalStatus.PENDING.value, "legacy-reviewer", None))

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                self.reviewer, approval.approval_id, True
            )

        self.assertEqual(self._raw_decision_state(approval.approval_id), before)

    def test_pending_approval_with_decided_at_fails_closed_without_mutation(self) -> None:
        approval = self._request()
        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET decided_at=? WHERE approval_id=?",
                ("2026-10-07T16:00:00+00:00", approval.approval_id),
            )

        before = self._raw_decision_state(approval.approval_id)
        self.assertEqual(
            before,
            (ApprovalStatus.PENDING.value, None, "2026-10-07T16:00:00+00:00"),
        )

        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                self.reviewer, approval.approval_id, False
            )

        self.assertEqual(self._raw_decision_state(approval.approval_id), before)

    def test_clean_pending_approval_remains_decidable(self) -> None:
        approval = self._request()

        decided = self.store.decide_risk_elevation(
            self.reviewer, approval.approval_id, True
        )

        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.decided_by, self.reviewer.user_id)
        self.assertIsNotNone(decided.decided_at)


if __name__ == "__main__":
    unittest.main()
