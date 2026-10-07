from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, ApprovalStatus, DomainStore, Role, RoleError
from lightup.engagements import RiskLevel


class _SwitchingApprovalId:
    """SQLite-adaptable identity that changes after the first bind."""

    def __init__(self, first: str, later: str) -> None:
        self.first = first
        self.later = later
        self.calls = 0

    def __conform__(self, protocol):
        if protocol is not sqlite3.PrepareProtocol:
            return None
        self.calls += 1
        return self.first if self.calls == 1 else self.later


class RiskDecisionApprovalIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-root", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_ctx = AccessContext(
            "client-admin", Role.CLIENT_ADMIN, self.client.client_id
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Approval identity boundary"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _pending(self, requester: AccessContext, suffix: str):
        return self.store.request_risk_elevation(
            requester,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            f"risk elevation request {suffix}",
        )

    def test_switching_sqlite_identity_is_rejected_before_first_bind(self) -> None:
        safe = self._pending(self.client_ctx, "safe-read")
        reviewer = AccessContext("op-reviewer", Role.OPERATOR)
        self_owned = self._pending(reviewer, "self-owned-mutation")

        forged = _SwitchingApprovalId(safe.approval_id, self_owned.approval_id)
        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(
                reviewer,
                forged,  # type: ignore[arg-type]
                True,
            )

        self.assertEqual(
            forged.calls,
            0,
            "non-canonical approval identity must fail before SQLite adaptation",
        )
        approvals = {
            record.approval_id: record
            for record in self.store.list_risk_approvals(
                self.client_ctx, self.engagement.engagement_id
            )
        }
        for approval_id in (safe.approval_id, self_owned.approval_id):
            self.assertIs(approvals[approval_id].status, ApprovalStatus.PENDING)
            self.assertIsNone(approvals[approval_id].decided_by)
            self.assertIsNone(approvals[approval_id].decided_at)

    def test_exact_string_identity_preserves_atomic_and_self_approval_controls(self) -> None:
        requester = AccessContext("op-requester", Role.OPERATOR)
        requested = self._pending(requester, "canonical-self-check")

        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(
                requester, requested.approval_id, True
            )

        reviewer = AccessContext("op-independent-reviewer", Role.OPERATOR)
        decided = self.store.decide_risk_elevation(
            reviewer, requested.approval_id, True
        )
        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.decided_by, reviewer.user_id)


if __name__ == "__main__":
    unittest.main()
