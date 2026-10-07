from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import (
    AccessContext,
    ApprovalStatus,
    DomainStore,
    Role,
    RoleError,
)
from lightup.engagements import RiskLevel


class _InequalitySpoofUserId(str):
    """Stores the same identity text while lying about equality."""

    def __eq__(self, other):
        return False

    def __ne__(self, other):
        return True


class RiskSelfApprovalIdentityAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.requester = AccessContext("op-self", Role.OPERATOR)
        self.client = self.store.create_client(self.requester, "Acme BV")
        self.engagement = self.store.create_engagement(
            self.requester,
            self.client.client_id,
            "Risk self-approval identity boundary",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _request(self):
        return self.store.request_risk_elevation(
            self.requester,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            "operator requests reviewed elevation",
        )

    def _persisted(self):
        return self.store.list_risk_approvals(
            self.requester,
            self.engagement.engagement_id,
        )[0]

    def test_canonical_same_operator_cannot_self_approve(self) -> None:
        approval = self._request()

        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(
                self.requester,
                approval.approval_id,
                True,
            )

        persisted = self._persisted()
        self.assertIs(persisted.status, ApprovalStatus.PENDING)
        self.assertIsNone(persisted.decided_by)
        self.assertIsNone(persisted.decided_at)

    def test_equality_spoofed_same_identity_cannot_bypass_self_approval_guard(self) -> None:
        approval = self._request()
        spoofed_same_operator = AccessContext(
            _InequalitySpoofUserId("op-self"),
            Role.OPERATOR,
        )

        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(
                spoofed_same_operator,
                approval.approval_id,
                True,
            )

        persisted = self._persisted()
        self.assertIs(persisted.status, ApprovalStatus.PENDING)
        self.assertIsNone(persisted.decided_by)
        self.assertIsNone(persisted.decided_at)

    def test_unrelated_canonical_operator_can_still_decide(self) -> None:
        approval = self._request()
        reviewer = AccessContext("op-reviewer", Role.OPERATOR)

        decided = self.store.decide_risk_elevation(
            reviewer,
            approval.approval_id,
            True,
        )

        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.decided_by, "op-reviewer")
        self.assertIsNotNone(decided.decided_at)


if __name__ == "__main__":
    unittest.main()
