from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class ElevatedGrantStepUpApprovalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-stepup-requester", Role.OPERATOR)
        self.reviewer = AccessContext("op-stepup-reviewer", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Step Up Client")

    def _engagement(self, name: str):
        return self.store.create_engagement(
            self.operator,
            self.client.client_id,
            name,
        )

    def _record_grant(self, engagement_id: str, risk: RiskLevel):
        now = datetime.now(timezone.utc)
        return self.store.record_authorization_grant(
            self.operator,
            engagement_id,
            approved_by="security-owner@example.test",
            reference="AUTH-STEPUP-1",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=risk,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(days=1),
        )

    def _approve_risk(
        self,
        engagement_id: str,
        risk: RiskLevel = RiskLevel.ELEVATED,
    ):
        approval = self.store.request_risk_elevation(
            self.operator,
            engagement_id,
            risk,
            "approved deeper assessment",
        )
        return self.store.decide_risk_elevation(
            self.reviewer,
            approval.approval_id,
            True,
        )

    def test_standard_grant_does_not_require_elevated_step_up(self):
        engagement = self._engagement("standard-control")

        grant = self._record_grant(
            engagement.engagement_id,
            RiskLevel.STANDARD,
        )

        self.assertIs(grant.scope.max_risk, RiskLevel.STANDARD)
        self.assertEqual(
            len(
                self.store.list_authorization_grants(
                    self.operator,
                    engagement.engagement_id,
                )
            ),
            1,
        )

    def test_elevated_grant_requires_approved_same_engagement_step_up(self):
        missing = self._engagement("missing")
        with self.assertRaises((PermissionError, ValueError)):
            self._record_grant(missing.engagement_id, RiskLevel.ELEVATED)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                missing.engagement_id,
            ),
            [],
        )

        pending = self._engagement("pending")
        self.store.request_risk_elevation(
            self.operator,
            pending.engagement_id,
            RiskLevel.ELEVATED,
            "pending step-up",
        )
        with self.assertRaises((PermissionError, ValueError)):
            self._record_grant(pending.engagement_id, RiskLevel.ELEVATED)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                pending.engagement_id,
            ),
            [],
        )

        denied = self._engagement("denied")
        denied_approval = self.store.request_risk_elevation(
            self.operator,
            denied.engagement_id,
            RiskLevel.ELEVATED,
            "denied step-up",
        )
        self.store.decide_risk_elevation(
            self.reviewer,
            denied_approval.approval_id,
            False,
        )
        with self.assertRaises((PermissionError, ValueError)):
            self._record_grant(denied.engagement_id, RiskLevel.ELEVATED)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                denied.engagement_id,
            ),
            [],
        )

        other = self._engagement("other-approved")
        self._approve_risk(other.engagement_id)
        target = self._engagement("cross-engagement-target")
        with self.assertRaises((PermissionError, ValueError)):
            self._record_grant(target.engagement_id, RiskLevel.ELEVATED)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                target.engagement_id,
            ),
            [],
        )

        underpowered = self._engagement("underpowered-approved")
        self._approve_risk(underpowered.engagement_id, RiskLevel.STANDARD)
        with self.assertRaises((PermissionError, ValueError)):
            self._record_grant(underpowered.engagement_id, RiskLevel.ELEVATED)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                underpowered.engagement_id,
            ),
            [],
        )

    def test_elevated_grant_accepts_approved_same_engagement_step_up(self):
        engagement = self._engagement("approved")
        self._approve_risk(engagement.engagement_id)

        grant = self._record_grant(
            engagement.engagement_id,
            RiskLevel.ELEVATED,
        )

        self.assertIs(grant.scope.max_risk, RiskLevel.ELEVATED)
        self.assertEqual(
            len(
                self.store.list_authorization_grants(
                    self.operator,
                    engagement.engagement_id,
                )
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
