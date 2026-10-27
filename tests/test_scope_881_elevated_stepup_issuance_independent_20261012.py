"""Offline real-SQLite elevated grant/step-up admission canaries for #881.

Source ownership belongs to domain grant/risk review maintainers. All fixtures
are disposable and synthetic. Expected failures are explicit, not authorization.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, ApprovalStatus, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class ElevatedGrantStepupIndependentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "synthetic-grants.sqlite"
        self.store = DomainStore(self.path)
        self.issuer = AccessContext("issuer-lab", Role.OPERATOR)
        self.reviewer = AccessContext("reviewer-lab", Role.OPERATOR)
        client_a = self.store.create_client(self.issuer, "Synthetic A")
        client_b = self.store.create_client(self.issuer, "Synthetic B")
        self.engagement = self.store.create_engagement(
            self.issuer, client_a.client_id, "isolated-A"
        )
        self.same_client_other_engagement = self.store.create_engagement(
            self.issuer, client_a.client_id, "isolated-A2"
        )
        self.other_client_engagement = self.store.create_engagement(
            self.issuer, client_b.client_id, "isolated-B"
        )
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(minutes=5)
        self.end = now + timedelta(hours=1)

    @contextmanager
    def _db(self):
        """Commit/rollback and *close* the sqlite handle deterministically."""
        con = sqlite3.connect(self.path)
        try:
            with con:
                yield con
        finally:
            con.close()

    def _grant_count(self) -> int:
        with self._db() as con:
            return con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]

    def _grant_rows(self):
        """Return a stable snapshot, not just a count, to prove denial atomicity."""
        with self._db() as con:
            return con.execute(
                "SELECT grant_id,client_id,engagement_id,max_risk,reference "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall()

    def _approval_rows(self):
        with self._db() as con:
            return con.execute(
                "SELECT approval_id,client_id,engagement_id,requested_risk,status "
                "FROM risk_approvals ORDER BY approval_id"
            ).fetchall()

    def _elevated(self):
        return self._issue(self.engagement.engagement_id, RiskLevel.ELEVATED)

    def _issue(self, engagement_id, risk):
        return self.store.record_authorization_grant(
            self.issuer,
            engagement_id,
            "lab reviewer (not human authorization)",
            "SYNTHETIC-LOCAL-ONLY",
            ScopeDefinition(assets=("127.0.0.1",), max_risk=risk),
            self.start,
            self.end,
        )

    def _stepup(self, engagement_id, risk=RiskLevel.ELEVATED, approve=True):
        request = self.store.request_risk_elevation(
            self.issuer,
            engagement_id,
            risk,
            "synthetic local risk decision only",
        )
        if approve is None:
            return request
        decision = self.store.decide_risk_elevation(self.reviewer, request.approval_id, approve)
        self.assertIs(decision.status, ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED)
        return decision

    def test_standard_grant_does_not_require_elevated_stepup(self):
        grant = self._issue(self.engagement.engagement_id, RiskLevel.STANDARD)
        self.assertEqual(grant.scope.max_risk, RiskLevel.STANDARD)
        self.assertEqual(self._grant_count(), 1)

    def test_elevated_grant_with_same_engagement_approved_stepup_is_control(self):
        self._stepup(self.engagement.engagement_id)
        grant = self._elevated()
        self.assertEqual(grant.engagement_id, self.engagement.engagement_id)
        self.assertEqual(grant.scope.max_risk, RiskLevel.ELEVATED)
        self.assertEqual(self._grant_count(), 1)

    def test_stepup_review_is_separate_operator(self):
        request = self._stepup(self.engagement.engagement_id, approve=None)
        with self.assertRaises(PermissionError):
            self.store.decide_risk_elevation(self.issuer, request.approval_id, True)
        self.assertEqual(self._grant_count(), 0)

    def test_standard_grant_not_blocked_by_pending_elevation(self):
        self._stepup(self.engagement.engagement_id, approve=None)
        before_approvals = self._approval_rows()
        grant = self._issue(self.engagement.engagement_id, RiskLevel.STANDARD)
        self.assertIs(grant.scope.max_risk, RiskLevel.STANDARD)
        self.assertEqual(self._grant_count(), 1)
        self.assertEqual(self._approval_rows(), before_approvals)

    def test_standard_grant_not_blocked_by_denied_elevation(self):
        self._stepup(self.engagement.engagement_id, approve=False)
        before_approvals = self._approval_rows()
        grant = self._issue(self.engagement.engagement_id, RiskLevel.STANDARD)
        self.assertIs(grant.scope.max_risk, RiskLevel.STANDARD)
        self.assertEqual(self._grant_count(), 1)
        self.assertEqual(self._approval_rows(), before_approvals)

    def test_approved_stepup_is_read_only_during_positive_elevated_issue(self):
        self._stepup(self.engagement.engagement_id, approve=True)
        approval_before = self._approval_rows()
        self._elevated()
        self.assertEqual(self._approval_rows(), approval_before)
        self.assertEqual(self._grant_count(), 1)

    @unittest.expectedFailure
    def test_red_pending_elevation_cannot_add_to_existing_standard_grant(self):
        # A refused ELEVATED issue must leave previously issued lower risk
        # authority intact instead of only asserting an empty grant table.
        self._issue(self.engagement.engagement_id, RiskLevel.STANDARD)
        self._stepup(self.engagement.engagement_id, approve=None)
        grants_before, approvals_before = self._grant_rows(), self._approval_rows()
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_rows(), grants_before)
        self.assertEqual(self._approval_rows(), approvals_before)

    @unittest.expectedFailure
    def test_red_wrong_tenant_stepup_cannot_modify_prior_grants(self):
        self._issue(self.engagement.engagement_id, RiskLevel.STANDARD)
        self._stepup(self.other_client_engagement.engagement_id)
        grants_before, approvals_before = self._grant_rows(), self._approval_rows()
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_rows(), grants_before)
        self.assertEqual(self._approval_rows(), approvals_before)

    @unittest.expectedFailure
    def test_red_elevated_grant_without_approval_must_leave_zero_rows(self):
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)

    @unittest.expectedFailure
    def test_red_pending_stepup_is_not_approval(self):
        self._stepup(self.engagement.engagement_id, approve=None)
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)

    @unittest.expectedFailure
    def test_red_denied_stepup_is_not_approval(self):
        self._stepup(self.engagement.engagement_id, approve=False)
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)

    @unittest.expectedFailure
    def test_red_approved_stepup_on_another_engagement_same_tenant_is_not_transferable(self):
        self._stepup(self.same_client_other_engagement.engagement_id)
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)

    @unittest.expectedFailure
    def test_red_approved_stepup_on_other_tenant_is_not_transferable(self):
        self._stepup(self.other_client_engagement.engagement_id)
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)

    @unittest.expectedFailure
    def test_red_lower_risk_approved_stepup_cannot_mint_elevated_scope(self):
        self._stepup(self.engagement.engagement_id, risk=RiskLevel.STANDARD)
        with self.assertRaises((PermissionError, ValueError)):
            self._elevated()
        self.assertEqual(self._grant_count(), 0)


if __name__ == "__main__":
    unittest.main()
