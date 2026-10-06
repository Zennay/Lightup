from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import (
    AccessContext,
    DomainStore,
    ApprovalStatus,
    RequestStatus,
    Role,
    RoleError,
    TenantIsolationError,
)
from lightup.engagements import (
    AssessmentMode,
    EngagementStatus,
    RiskLevel,
    ScopeDefinition,
)
from lightup.models import RetestStatus, Severity


def _grant_window():
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=1), now + timedelta(days=30)


class DomainStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")
        self.ctx_a = AccessContext("user-a", Role.CLIENT_ADMIN, self.client_a.client_id)
        self.ctx_b = AccessContext("user-b", Role.CLIENT_ADMIN, self.client_b.client_id)

    def tearDown(self):
        self.tmp.cleanup()

    def test_operator_context_cannot_bind_client(self):
        with self.assertRaises(ValueError):
            AccessContext("x", Role.OPERATOR, "some-client")
        with self.assertRaises(ValueError):
            AccessContext("x", Role.CLIENT_ADMIN, None)

    def test_client_cannot_create_clients_or_users(self):
        with self.assertRaises(RoleError):
            self.store.create_client(self.ctx_a, "Evil")
        with self.assertRaises(RoleError):
            self.store.create_user(self.ctx_a, "a@a.example", "A", Role.CLIENT_ADMIN,
                                   self.client_a.client_id)

    def test_tenant_isolation_on_reads(self):
        self.store.submit_assessment_request(
            self.ctx_a, ("app.acme.example",), AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )
        # Client B sees nothing of client A.
        self.assertEqual(self.store.list_assessment_requests(self.ctx_b), [])
        # Explicitly asking for the other tenant fails closed.
        with self.assertRaises(TenantIsolationError):
            self.store.list_assessment_requests(self.ctx_b, client_id=self.client_a.client_id)
        with self.assertRaises(TenantIsolationError):
            self.store.get_client(self.ctx_b, self.client_a.client_id)

    def test_tenant_isolation_on_record_access(self):
        request = self.store.submit_assessment_request(
            self.ctx_a, ("app.acme.example",), AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )
        with self.assertRaises(TenantIsolationError):
            self.store.get_assessment_request(self.ctx_b, request.request_id)
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        with self.assertRaises(TenantIsolationError):
            self.store.get_engagement(self.ctx_b, engagement.engagement_id)
        finding = self.store.record_finding(
            self.operator, engagement.engagement_id, "Weak TLS", Severity.MEDIUM,
            "app.acme.example", "Downgrade possible", "Enable TLS 1.2+ only",
        )
        self.assertEqual(self.store.list_findings(self.ctx_b), [])
        self.assertEqual(self.store.list_findings(self.ctx_a)[0].finding_id,
                         finding.finding_id)

    def test_client_cannot_submit_for_other_tenant(self):
        with self.assertRaises(TenantIsolationError):
            self.store.submit_assessment_request(
                self.ctx_a, ("x",), AssessmentMode.AUTHORIZED_ASSESSMENT,
                RiskLevel.STANDARD, client_id=self.client_b.client_id,
            )

    def test_assessment_request_rejects_invalid_or_destructive_risk(self):
        invalid_cases = (
            ("authorized_assessment", RiskLevel.STANDARD),
            (AssessmentMode.AUTHORIZED_ASSESSMENT, 5),
            (AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.DESTRUCTIVE_LAB_ONLY),
        )
        for index, (mode, risk) in enumerate(invalid_cases):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    self.store.submit_assessment_request(
                        self.ctx_a,
                        ("app.acme.example",),
                        mode,  # type: ignore[arg-type]
                        risk,  # type: ignore[arg-type]
                    )
        self.assertEqual(self.store.list_assessment_requests(self.ctx_a), [])

    def test_assessment_decision_requires_bool_and_revalidates_legacy_risk(self):
        request = self.store.submit_assessment_request(
            self.ctx_a,
            ("app.acme.example",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )
        with self.assertRaisesRegex(ValueError, "decision must be a bool"):
            self.store.review_assessment_request(
                self.operator, request.request_id, "false"  # type: ignore[arg-type]
            )
        self.assertIs(
            self.store.get_assessment_request(self.operator, request.request_id).status,
            RequestStatus.SUBMITTED,
        )

        with self.store._connect() as con:
            con.execute(
                "UPDATE assessment_requests SET requested_risk=? WHERE request_id=?",
                (int(RiskLevel.DESTRUCTIVE_LAB_ONLY), request.request_id),
            )
        with self.assertRaisesRegex(ValueError, "destructive lab risk"):
            self.store.review_assessment_request(
                self.operator, request.request_id, True
            )
        self.assertIs(
            self.store.get_assessment_request(self.operator, request.request_id).status,
            RequestStatus.SUBMITTED,
        )

    def test_request_review_is_operator_only(self):
        request = self.store.submit_assessment_request(
            self.ctx_a, ("app.acme.example",), AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )
        with self.assertRaises(RoleError):
            self.store.review_assessment_request(self.ctx_a, request.request_id, True)
        decided = self.store.review_assessment_request(self.operator, request.request_id, True)
        self.assertIs(decided.status, RequestStatus.APPROVED)
        with self.assertRaises(ValueError):
            self.store.review_assessment_request(self.operator, request.request_id, False)

    def test_authorization_grant_roundtrip_and_validity(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        valid_from, valid_until = _grant_window()
        scope = ScopeDefinition(
            assets=("app.acme.example",), max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",), excluded_assets=("legacy.acme.example",),
        )
        grant = self.store.record_authorization_grant(
            self.operator, engagement.engagement_id, "CISO Acme", "AUTH-2026-001",
            scope, valid_from, valid_until,
        )
        current = self.store.get_current_grant(self.ctx_a, engagement.engagement_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.grant_id, grant.grant_id)
        self.assertEqual(current.scope, scope)
        self.assertTrue(current.scope.allows_asset("app.acme.example"))
        self.assertFalse(current.scope.allows_asset("legacy.acme.example"))
        # Expired window yields no current grant.
        future = datetime.now(timezone.utc) + timedelta(days=90)
        self.assertIsNone(self.store.get_current_grant(
            self.ctx_a, engagement.engagement_id, now=future))

    def test_grants_are_operator_only_and_validated(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        valid_from, valid_until = _grant_window()
        scope = ScopeDefinition(assets=("a",), max_risk=RiskLevel.STANDARD)
        with self.assertRaises(RoleError):
            self.store.record_authorization_grant(
                self.ctx_a, engagement.engagement_id, "x", "ref", scope,
                valid_from, valid_until,
            )
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, engagement.engagement_id, "x", "ref", scope,
                valid_until, valid_from,  # empty window
            )
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, engagement.engagement_id, "x", "ref",
                ScopeDefinition(assets=(), max_risk=RiskLevel.STANDARD),
                valid_from, valid_until,
            )

    def test_persisted_grant_requires_explicit_known_non_lab_capabilities(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Strict scope"
        )
        valid_from, valid_until = _grant_window()

        invalid_scopes = (
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(),
            ),
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("future-unknown-capability",),
            ),
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("wireless-lab",),
            ),
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                allowed_capabilities=("web-baseline",),
            ),
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=5,  # type: ignore[arg-type]
                allowed_capabilities=("web-baseline",),
            ),
        )
        for index, scope in enumerate(invalid_scopes):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    self.store.record_authorization_grant(
                        self.operator,
                        engagement.engagement_id,
                        "CISO Acme",
                        f"AUTH-INVALID-{index}",
                        scope,
                        valid_from,
                        valid_until,
                    )
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, engagement.engagement_id
            ),
            [],
        )

    def test_recurring_retest_authority_requires_real_bool(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Retest authority boundary"
        )
        valid_from, valid_until = _grant_window()
        scope = ScopeDefinition(
            assets=("app.acme.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )

        with self.assertRaisesRegex(ValueError, "recurring_retest_allowed must be a bool"):
            self.store.record_authorization_grant(
                self.operator,
                engagement.engagement_id,
                "CISO Acme",
                "AUTH-RETEST-INVALID",
                scope,
                valid_from,
                valid_until,
                recurring_retest_allowed="false",  # type: ignore[arg-type]
            )
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, engagement.engagement_id
            ),
            [],
        )

        false_grant = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-RETEST-FALSE",
            scope,
            valid_from,
            valid_until,
            recurring_retest_allowed=False,
        )
        true_grant = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-RETEST-TRUE",
            scope,
            valid_from,
            valid_until,
            recurring_retest_allowed=True,
        )
        persisted = {
            grant.grant_id: grant
            for grant in self.store.list_authorization_grants(
                self.operator, engagement.engagement_id
            )
        }
        self.assertFalse(persisted[false_grant.grant_id].recurring_retest_allowed)
        self.assertTrue(persisted[true_grant.grant_id].recurring_retest_allowed)

    def test_invalid_persisted_recurring_retest_flag_fails_closed(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Persisted retest flag boundary"
        )
        valid_from, valid_until = _grant_window()
        grant = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-RETEST-PERSISTED",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from,
            valid_until,
            recurring_retest_allowed=False,
        )
        with self.store._connect() as con:
            con.execute(
                "UPDATE authorization_grants SET recurring_retest_allowed=? WHERE grant_id=?",
                (2, grant.grant_id),
            )
        with self.assertRaisesRegex(ValueError, "persisted recurring_retest_allowed"):
            self.store.list_authorization_grants(
                self.operator, engagement.engagement_id
            )

    def test_revoke_engagement_authorization_revokes_current_and_future_grants(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Emergency scope"
        )
        now = datetime.now(timezone.utc)
        current = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-CURRENT",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(days=2),
        )
        future = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-FUTURE",
            ScopeDefinition(
                assets=("api.acme.example",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("api-baseline",),
            ),
            now + timedelta(days=3),
            now + timedelta(days=5),
        )
        self.assertEqual(
            self.store.get_current_grant(self.operator, engagement.engagement_id).grant_id,
            current.grant_id,
        )

        revoked = self.store.revoke_engagement_authorization(
            self.operator, engagement.engagement_id, "customer withdrew authorization"
        )

        self.assertEqual(
            {grant.grant_id for grant in revoked}, {current.grant_id, future.grant_id}
        )
        self.assertIsNone(
            self.store.get_current_grant(self.operator, engagement.engagement_id)
        )
        for grant in self.store.list_authorization_grants(
            self.operator, engagement.engagement_id
        ):
            self.assertTrue(grant.is_revoked)
            self.assertEqual(grant.revoked_by, self.operator.user_id)
            self.assertEqual(
                grant.revocation_reason, "customer withdrew authorization"
            )
            self.assertIsNotNone(grant.revoked_at)
        self.assertEqual(
            self.store.revoke_engagement_authorization(
                self.operator, engagement.engagement_id, "repeat withdrawal"
            ),
            (),
        )

    def test_execution_resolver_reloads_live_grant_and_revocation(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Execution resolver"
        )
        valid_from, valid_until = _grant_window()
        snapshot = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-LIVE-RESOLVE",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from,
            valid_until,
        )

        live = self.store.resolve_authorization_for_execution(snapshot)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, snapshot.grant_id)
        self.assertFalse(live.is_revoked)

        self.store.revoke_engagement_authorization(
            self.operator,
            engagement.engagement_id,
            "client withdrew authorization",
        )
        self.assertIsNone(
            self.store.resolve_authorization_for_execution(snapshot),
            "stale in-memory grant must not survive durable revocation",
        )

    def test_execution_resolver_denies_closed_engagement(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Closed execution boundary"
        )
        valid_from, valid_until = _grant_window()
        snapshot = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-CLOSED-ENGAGEMENT",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from,
            valid_until,
        )
        self.assertIsNotNone(
            self.store.resolve_authorization_for_execution(snapshot)
        )

        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.CLOSED
        )
        self.assertIsNone(
            self.store.resolve_authorization_for_execution(snapshot),
            "closed engagement must invalidate target-active authorization",
        )
        closed_grant = self.store.list_authorization_grants(
            self.operator, engagement.engagement_id
        )[0]
        self.assertTrue(closed_grant.is_revoked)
        self.assertEqual(closed_grant.revoked_by, self.operator.user_id)
        self.assertEqual(closed_grant.revocation_reason, "engagement closed")

        # Reopening the lifecycle record cannot revive historical authorization.
        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.DRAFT
        )
        self.assertIsNone(
            self.store.resolve_authorization_for_execution(snapshot)
        )
        self.assertIsNone(
            self.store.get_current_grant(self.operator, engagement.engagement_id)
        )

    def test_closed_engagement_rejects_new_grants_until_reopened(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Closed grant boundary"
        )
        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.CLOSED
        )
        valid_from, valid_until = _grant_window()
        with self.assertRaisesRegex(
            ValueError, "closed engagement cannot receive authorization grants"
        ):
            self.store.record_authorization_grant(
                self.operator,
                engagement.engagement_id,
                "CISO Acme",
                "AUTH-AFTER-CLOSE",
                ScopeDefinition(
                    assets=("app.acme.example",),
                    max_risk=RiskLevel.STANDARD,
                    allowed_capabilities=("web-baseline",),
                ),
                valid_from,
                valid_until,
            )

        # A deliberately reopened engagement can only gain authority from a new grant.
        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.DRAFT
        )
        fresh = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-AFTER-REOPEN",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from,
            valid_until,
        )
        self.assertEqual(
            self.store.get_current_grant(
                self.operator, engagement.engagement_id
            ).grant_id,
            fresh.grant_id,
        )

    def test_authorization_revocation_is_operator_only_and_requires_reason(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Revocation boundary"
        )
        valid_from, valid_until = _grant_window()
        self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            "CISO Acme",
            "AUTH-REVOKE",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from,
            valid_until,
        )
        with self.assertRaises(RoleError):
            self.store.revoke_engagement_authorization(
                self.ctx_a, engagement.engagement_id, "not allowed"
            )
        with self.assertRaises(ValueError):
            self.store.revoke_engagement_authorization(
                self.operator, engagement.engagement_id, "   "
            )
        self.assertIsNotNone(
            self.store.get_current_grant(self.operator, engagement.engagement_id)
        )

    def test_legacy_authorization_table_migrates_revocation_columns(self):
        path = Path(self.tmp.name) / "legacy-domain.db"
        con = sqlite3.connect(path)
        con.execute(
            """
            CREATE TABLE authorization_grants (
                grant_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                reference TEXT NOT NULL,
                assets_json TEXT NOT NULL,
                excluded_assets_json TEXT NOT NULL,
                allowed_capabilities_json TEXT NOT NULL,
                max_risk INTEGER NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT NOT NULL,
                recurring_retest_allowed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        con.close()

        DomainStore(path)

        con = sqlite3.connect(path)
        try:
            columns = {
                row[1] for row in con.execute(
                    "PRAGMA table_info(authorization_grants)"
                ).fetchall()
            }
        finally:
            con.close()
        self.assertTrue(
            {"revoked_at", "revoked_by", "revocation_reason"}.issubset(columns)
        )

    def test_risk_elevation_rejects_invalid_or_destructive_risk(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Risk intake boundary"
        )
        for index, risk in enumerate((5, RiskLevel.DESTRUCTIVE_LAB_ONLY)):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    self.store.request_risk_elevation(
                        self.ctx_a,
                        engagement.engagement_id,
                        risk,  # type: ignore[arg-type]
                        "request that must fail before persistence",
                    )
        self.assertEqual(
            self.store.list_risk_approvals(self.ctx_a, engagement.engagement_id),
            [],
        )

    def test_risk_decision_requires_bool_and_revalidates_legacy_risk(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Risk decision boundary"
        )
        approval = self.store.request_risk_elevation(
            self.ctx_a,
            engagement.engagement_id,
            RiskLevel.ELEVATED,
            "request pending operator review",
        )
        reviewer = AccessContext("op-reviewer", Role.OPERATOR)

        with self.assertRaisesRegex(ValueError, "decision must be a bool"):
            self.store.decide_risk_elevation(
                reviewer, approval.approval_id, "false"  # type: ignore[arg-type]
            )
        self.assertIs(
            self.store.list_risk_approvals(
                self.ctx_a, engagement.engagement_id
            )[0].status,
            ApprovalStatus.PENDING,
        )

        with self.store._connect() as con:
            con.execute(
                "UPDATE risk_approvals SET requested_risk=? WHERE approval_id=?",
                (int(RiskLevel.DESTRUCTIVE_LAB_ONLY), approval.approval_id),
            )
        with self.assertRaisesRegex(ValueError, "destructive lab risk"):
            self.store.decide_risk_elevation(
                reviewer, approval.approval_id, True
            )
        self.assertIs(
            self.store.list_risk_approvals(
                self.ctx_a, engagement.engagement_id
            )[0].status,
            ApprovalStatus.PENDING,
        )

    def test_risk_elevation_requires_second_operator(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        approval = self.store.request_risk_elevation(
            self.operator, engagement.engagement_id, RiskLevel.ELEVATED, "deeper auth testing",
        )
        self.assertIs(approval.status, ApprovalStatus.PENDING)
        # The requesting operator cannot approve their own elevation.
        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(self.operator, approval.approval_id, True)
        # A client can never decide.
        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(self.ctx_a, approval.approval_id, True)
        other = AccessContext("op-2", Role.OPERATOR)
        decided = self.store.decide_risk_elevation(other, approval.approval_id, True)
        self.assertIs(decided.status, ApprovalStatus.APPROVED)
        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(other, approval.approval_id, False)

    def test_retest_status_updates(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        finding = self.store.record_finding(
            self.operator, engagement.engagement_id, "Weak TLS", Severity.MEDIUM,
            "app.acme.example", "Downgrade possible", "Enable TLS 1.2+ only",
        )
        with self.assertRaises(RoleError):
            self.store.set_retest_status(self.ctx_a, finding.finding_id, RetestStatus.FIXED)
        updated = self.store.set_retest_status(
            self.operator, finding.finding_id, RetestStatus.FIXED)
        self.assertIs(updated.retest_status, RetestStatus.FIXED)

    def test_prospects_are_operator_only(self):
        self.store.add_prospect(self.operator, "Initech", "Exposed admin panel signal", 0.6)
        with self.assertRaises(RoleError):
            self.store.list_prospects(self.ctx_a)
        with self.assertRaises(RoleError):
            self.store.add_prospect(self.ctx_a, "X", "y", 0.5)
        self.assertEqual(len(self.store.list_prospects(self.operator)), 1)

    def test_context_for_user(self):
        user = self.store.create_user(
            self.operator, "a@acme.example", "A", Role.CLIENT_ADMIN, self.client_a.client_id)
        ctx = self.store.context_for_user(user.user_id)
        self.assertEqual(ctx.client_id, self.client_a.client_id)
        self.assertFalse(ctx.is_operator)


if __name__ == "__main__":
    unittest.main()
