from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel, ScopeDefinition


class RequestGrantBindingAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-request-grant", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Request Grant Client")
        self.other_client = self.store.create_client(
            self.operator, "Other Request Grant Client"
        )
        self.client_ctx = AccessContext(
            "client-admin-request-grant", Role.CLIENT_ADMIN, self.client.client_id
        )
        self.other_client_ctx = AccessContext(
            "other-client-admin-request-grant",
            Role.CLIENT_ADMIN,
            self.other_client.client_id,
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Request grant binding"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def _window() -> tuple[datetime, datetime]:
        now = datetime.now(timezone.utc)
        return now - timedelta(hours=1), now + timedelta(days=7)

    @staticmethod
    def _scope(
        asset: str = "app.request-grant.example",
        max_risk: RiskLevel = RiskLevel.STANDARD,
    ) -> ScopeDefinition:
        return ScopeDefinition(
            assets=(asset,),
            max_risk=max_risk,
            allowed_capabilities=("web-baseline",),
        )

    def _record(self, scope: ScopeDefinition | None = None):
        valid_from, valid_until = self._window()
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Request Grant",
            "AUTH-REQUEST-GRANT-001",
            scope or self._scope(),
            valid_from,
            valid_until,
        )

    def _submit(
        self,
        *,
        ctx: AccessContext | None = None,
        asset: str = "app.request-grant.example",
        mode: AssessmentMode = AssessmentMode.AUTHORIZED_ASSESSMENT,
        risk: RiskLevel = RiskLevel.STANDARD,
    ):
        return self.store.submit_assessment_request(
            ctx or self.client_ctx,
            (asset,),
            mode,
            risk,
        )

    def _approve(self, request) -> None:
        self.store.review_assessment_request(
            self.operator, request.request_id, True
        )

    def test_matching_approved_request_allows_grant(self) -> None:
        request = self._submit()
        self._approve(request)
        grant = self._record()
        self.assertEqual(grant.client_id, self.client.client_id)

    def test_missing_approved_request_cannot_authorize_grant(self) -> None:
        with self.assertRaises(ValueError):
            self._record()

    def test_pending_request_cannot_authorize_grant(self) -> None:
        self._submit()
        with self.assertRaises(ValueError):
            self._record()

    def test_rejected_request_cannot_authorize_grant(self) -> None:
        request = self._submit()
        self.store.review_assessment_request(
            self.operator, request.request_id, False
        )
        with self.assertRaises(ValueError):
            self._record()

    def test_other_clients_approved_request_cannot_authorize_grant(self) -> None:
        request = self._submit(ctx=self.other_client_ctx)
        self._approve(request)
        with self.assertRaises(ValueError):
            self._record()

    def test_non_authorized_assessment_mode_cannot_authorize_grant(self) -> None:
        request = self._submit(mode=AssessmentMode.PASSIVE_DISCOVERY)
        self._approve(request)
        with self.assertRaises(ValueError):
            self._record()

    def test_grant_asset_must_be_covered_by_approved_request(self) -> None:
        request = self._submit(asset="app.request-grant.example")
        self._approve(request)
        with self.assertRaises(ValueError):
            self._record(self._scope(asset="other.request-grant.example"))

    def test_grant_risk_must_not_exceed_approved_request(self) -> None:
        request = self._submit(risk=RiskLevel.LOW_IMPACT)
        self._approve(request)
        with self.assertRaises(ValueError):
            self._record(self._scope(max_risk=RiskLevel.STANDARD))


if __name__ == "__main__":
    unittest.main()
