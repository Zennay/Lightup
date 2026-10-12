"""Real SQLite snapshots evaluated by an UNINSTALLED risk step-up reference."""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel
from scope_881_stepup_snapshot_reference import check_synthetic_stepup_snapshot


class RiskStepupSnapshotReferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "risk-reference.sqlite")
        self.requester = AccessContext("requester-fixture", Role.OPERATOR)
        self.reviewer = AccessContext("reviewer-fixture", Role.OPERATOR)
        c1 = self.store.create_client(self.requester, "Synthetic Tenant A")
        c2 = self.store.create_client(self.requester, "Synthetic Tenant B")
        self.engagement = self.store.create_engagement(
            self.requester, c1.client_id, "synthetic engagement A1"
        )
        self.other_same_client = self.store.create_engagement(
            self.requester, c1.client_id, "synthetic engagement A2"
        )
        self.other_client = self.store.create_engagement(
            self.requester, c2.client_id, "synthetic engagement B"
        )

    def _request(self, engagement, risk=RiskLevel.ELEVATED, approval=True):
        original = self.store.request_risk_elevation(
            self.requester,
            engagement.engagement_id,
            risk,
            "inert synthetic stepup evidence only",
        )
        if approval is None:
            return original
        return self.store.decide_risk_elevation(
            self.reviewer, original.approval_id, approval
        )

    def _snapshot(self):
        return tuple(self.store.list_risk_approvals(self.requester))

    def _check(self, requested_risk=RiskLevel.ELEVATED, approvals=None):
        if approvals is None:
            approvals = self._snapshot()
        return check_synthetic_stepup_snapshot(
            client_id=self.engagement.client_id,
            engagement_id=self.engagement.engagement_id,
            requested_risk=requested_risk,
            approvals=approvals,
        )

    def test_ordinary_standard_can_still_pass_with_no_elevation(self):
        self.assertIsNone(self._check(RiskLevel.STANDARD))
        self.assertEqual(self._snapshot(), ())

    def test_valid_approved_same_engagement_matches_without_side_effect(self):
        self._request(self.engagement)
        before = self._snapshot()
        self.assertIsNone(self._check())
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.requester, self.engagement.engagement_id
            ),
            [],
        )

    def test_pending_review_does_not_authorize_elevated(self):
        self._request(self.engagement, approval=None)
        before = self._snapshot()
        with self.assertRaises(PermissionError):
            self._check()
        self.assertEqual(self._snapshot(), before)

    def test_denied_review_does_not_authorize_elevated(self):
        self._request(self.engagement, approval=False)
        with self.assertRaises(PermissionError):
            self._check()

    def test_other_engagement_same_client_cannot_authorize(self):
        self._request(self.other_same_client)
        with self.assertRaises(PermissionError):
            self._check()

    def test_other_tenant_review_cannot_authorize(self):
        self._request(self.other_client)
        with self.assertRaises(PermissionError):
            self._check()

    def test_lower_approved_risk_cannot_authorize_elevated(self):
        self._request(self.engagement, risk=RiskLevel.STANDARD)
        with self.assertRaises(PermissionError):
            self._check()

    def test_foreign_approved_plus_own_pending_still_denies(self):
        self._request(self.other_client)
        self._request(self.engagement, approval=None)
        with self.assertRaises(PermissionError):
            self._check()

    def test_approved_plus_denied_review_does_not_erase_valid_evidence(self):
        self._request(self.engagement, approval=False)
        self._request(self.engagement, approval=True)
        before = self._snapshot()
        self.assertIsNone(self._check())
        self.assertEqual(self._snapshot(), before)

    def test_strict_type_and_record_shape_rejection(self):
        self._request(self.engagement)
        known = self._snapshot()
        with self.assertRaises(PermissionError):
            self._check(requested_risk=int(RiskLevel.ELEVATED))
        with self.assertRaises(PermissionError):
            self._check(approvals=list(known))
        with self.assertRaises(PermissionError):
            self._check(approvals=known + (object(),))
        with self.assertRaises(PermissionError):
            self._check(approvals=(replace(known[0], status="approved"),))
        with self.assertRaises(PermissionError):
            self._check(approvals=(replace(known[0], requested_risk=4),))
        self.assertEqual(self._snapshot(), known)

    def test_risk_five_requires_separate_lab_only_review(self):
        self._request(self.engagement, risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)
        with self.assertRaises(PermissionError):
            self._check(RiskLevel.DESTRUCTIVE_LAB_ONLY)

    def test_noncanonical_context_is_rejected(self):
        with self.assertRaises(ValueError):
            check_synthetic_stepup_snapshot(
                client_id=self.engagement.client_id + " ",
                engagement_id=self.engagement.engagement_id,
                requested_risk=RiskLevel.STANDARD,
                approvals=(),
            )


if __name__ == "__main__":
    unittest.main()
