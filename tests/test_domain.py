from __future__ import annotations

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
from lightup.engagements import AssessmentMode, RiskLevel, ScopeDefinition
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

    def test_coverage_rejects_unknown_capability_before_persistence(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Coverage boundary"
        )

        class ForgedCapabilityId(str):
            pass

        for capability_id in (
            "",
            "unknown-capability",
            ForgedCapabilityId("web-baseline"),
        ):
            with self.subTest(capability_id=capability_id):
                with self.assertRaises(ValueError):
                    self.store.set_coverage(
                        self.operator,
                        engagement.engagement_id,
                        capability_id,
                        "assessed",
                    )

        self.assertEqual(
            self.store.get_coverage(self.ctx_a, engagement.engagement_id),
            {},
        )

        self.store.set_coverage(
            self.operator,
            engagement.engagement_id,
            "web-baseline",
            "assessed",
        )
        self.assertEqual(
            self.store.get_coverage(self.ctx_a, engagement.engagement_id),
            {"web-baseline": "assessed"},
        )

    def test_coverage_rejects_noncanonical_status_before_persistence(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Coverage status boundary"
        )

        class ForgedCoverageStatus(str):
            pass

        for status in ("not-a-status", ForgedCoverageStatus("assessed")):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    self.store.set_coverage(
                        self.operator,
                        engagement.engagement_id,
                        "web-baseline",
                        status,
                    )

        self.assertEqual(
            self.store.get_coverage(self.ctx_a, engagement.engagement_id),
            {},
        )

        self.store.set_coverage(
            self.operator,
            engagement.engagement_id,
            "web-baseline",
            "partially_assessed",
        )
        self.assertEqual(
            self.store.get_coverage(self.ctx_a, engagement.engagement_id),
            {"web-baseline": "partially_assessed"},
        )

    def test_coverage_read_rejects_corrupt_durable_rows_without_repair(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Coverage read boundary"
        )
        corrupt_cases = (
            ("unknown-capability", "assessed"),
            ("web-baseline", "not-a-status"),
        )

        for index, (capability_id, status) in enumerate(corrupt_cases):
            with self.subTest(index=index):
                with self.store._connect() as con:
                    con.execute(
                        "INSERT INTO coverage_entries("
                        "engagement_id,capability_id,status,updated_at"
                        ") VALUES(?,?,?,?)",
                        (
                            engagement.engagement_id,
                            capability_id,
                            status,
                            "2026-10-07T00:00:00+00:00",
                        ),
                    )

                with self.assertRaises(ValueError):
                    self.store.get_coverage(self.ctx_a, engagement.engagement_id)

                with self.store._connect() as con:
                    persisted = con.execute(
                        "SELECT capability_id,status FROM coverage_entries "
                        "WHERE engagement_id=?",
                        (engagement.engagement_id,),
                    ).fetchall()
                    self.assertEqual(
                        [(row["capability_id"], row["status"]) for row in persisted],
                        [(capability_id, status)],
                    )
                    con.execute(
                        "DELETE FROM coverage_entries WHERE engagement_id=?",
                        (engagement.engagement_id,),
                    )

        self.store.set_coverage(
            self.operator,
            engagement.engagement_id,
            "web-baseline",
            "assessed",
        )
        self.assertEqual(
            self.store.get_coverage(self.ctx_a, engagement.engagement_id),
            {"web-baseline": "assessed"},
        )

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
