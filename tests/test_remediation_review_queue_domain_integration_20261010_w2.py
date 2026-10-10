"""Real DomainStore producer -> offline remediation triage integration.

Only temporary SQLite under tempfile. This does not connect to production,
issue operator approvals, access real targets, or authorize assessment work.
"""
from __future__ import annotations

from dataclasses import replace
import tempfile
from pathlib import Path
import unittest

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.models import RetestStatus, Severity
from lightup.remediation_review_queue import build_remediation_review_queue
from lightup.remediation_review_source import read_remediation_review_queue


class RemediationReviewDomainIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "domain.sqlite")
        self.operator = AccessContext("operator-test", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Synthetic A")
        self.client_b = self.store.create_client(self.operator, "Synthetic B")
        self.engagement_a = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Authorized A"
        )
        self.engagement_b = self.store.create_engagement(
            self.operator, self.client_b.client_id, "Authorized B"
        )
        self.a = self.store.record_finding(
            self.operator,
            self.engagement_a.engagement_id,
            title="Sensitive A title",
            severity=Severity.HIGH,
            asset="lab://a",
            impact="private impact A",
            remediation="Synthetic remediation A",
            evidence_ids=("evidence-a",),
        )
        self.b = self.store.record_finding(
            self.operator,
            self.engagement_b.engagement_id,
            title="Sensitive B title",
            severity=Severity.CRITICAL,
            asset="lab://b",
            impact="private impact B",
            remediation="Synthetic remediation B",
            evidence_ids=("evidence-b",),
        )

    def _rows(self, engagement_id: str):
        return tuple(self.store.list_findings(
            self.operator, engagement_id=engagement_id,
        ))

    def test_real_tenant_selected_rows_make_bounded_non_authorizing_queue(self):
        selected = self._rows(self.engagement_a.engagement_id)
        self.assertEqual(len(selected), 1)
        review = build_remediation_review_queue(
            selected,
            client_id=self.client_a.client_id,
            engagement_id=self.engagement_a.engagement_id,
        )
        self.assertEqual(len(review.items), 1)
        self.assertEqual(review.items[0].referenced_evidence_count, 1)
        self.assertEqual(review.items[0].next_review_step, "review_remediation")
        self.assertFalse(review.authorization_verified)
        self.assertFalse(review.release_authorized)
        text = review.to_json()
        for forbidden in (
            self.a.finding_id, self.client_a.client_id, self.engagement_a.engagement_id,
            "lab://a", "Sensitive A", "evidence-a", "Synthetic remediation A",
        ):
            self.assertNotIn(forbidden, text)

    def test_real_domain_cross_tenant_read_is_rejected_before_advisory(self):
        client_context = AccessContext(
            "client-a-member", Role.CLIENT_MEMBER, self.client_a.client_id,
        )
        with self.assertRaises(TenantIsolationError):
            self.store.list_findings(
                client_context, engagement_id=self.engagement_b.engagement_id,
            )

    def test_mixed_real_client_records_fail_before_queue_publication(self):
        selected = self._rows(self.engagement_a.engagement_id) + self._rows(
            self.engagement_b.engagement_id
        )
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            build_remediation_review_queue(
                selected,
                client_id=self.client_a.client_id,
                engagement_id=self.engagement_a.engagement_id,
            )

    def test_retest_claim_never_turns_into_fix_certification(self):
        selected = self._rows(self.engagement_a.engagement_id)
        claimed = (replace(selected[0], retest_status=RetestStatus.FIXED),)
        review = build_remediation_review_queue(
            claimed,
            client_id=self.client_a.client_id,
            engagement_id=self.engagement_a.engagement_id,
        )
        self.assertEqual(review.items[0].next_review_step, "independent_retest")
        self.assertFalse(review.items[0].fix_verified)
        self.assertFalse(review.retest_authorized)
        # No durable retest-status mutation from an advisory.
        self.assertEqual(
            self._rows(self.engagement_a.engagement_id)[0].retest_status,
            RetestStatus.NOT_TESTED,
        )

    def test_repeated_advisory_does_not_write_any_domain_rows(self):
        selected = self._rows(self.engagement_a.engagement_id)
        with self.store._connect() as con:
            before = con.execute(
                "SELECT finding_id, evidence_ids_json, retest_status "
                "FROM findings ORDER BY finding_id",
            ).fetchall()
            snapshot = [tuple(row) for row in before]
        first = build_remediation_review_queue(
            selected,
            client_id=self.client_a.client_id,
            engagement_id=self.engagement_a.engagement_id,
        )
        second = build_remediation_review_queue(
            selected,
            client_id=self.client_a.client_id,
            engagement_id=self.engagement_a.engagement_id,
        )
        self.assertEqual(first, second)
        with self.store._connect() as con:
            after = con.execute(
                "SELECT finding_id, evidence_ids_json, retest_status "
                "FROM findings ORDER BY finding_id",
            ).fetchall()
            self.assertEqual([tuple(row) for row in after], snapshot)


    def test_real_persisted_regression_with_two_missing_inputs_lists_all_review_needs(self):
        finding = self.store.record_finding(
            self.operator,
            self.engagement_a.engagement_id,
            title="Private missing evidence and remediation fixture",
            severity=Severity.CRITICAL,
            asset="lab://remediation-regression",
            impact="private failure details",
            remediation="Synthetic initial human-authored remediation",
            evidence_ids=(),
        )
        # DomainStore correctly refuses empty remediation at creation; emulate
        # a legacy/imported incomplete row in this disposable local database.
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET remediation='' WHERE finding_id=?",
                (finding.finding_id,),
            )
        self.store.set_retest_status(
            self.operator, finding.finding_id, RetestStatus.REGRESSION,
        )
        with self.store._connect() as con:
            before = [
                tuple(row) for row in con.execute(
                    "SELECT finding_id,client_id,engagement_id,remediation,"
                    "evidence_ids_json,retest_status FROM findings "
                    "ORDER BY finding_id",
                ).fetchall()
            ]
        client = AccessContext(
            "client-a-member", Role.CLIENT_MEMBER, self.client_a.client_id,
        )
        result = read_remediation_review_queue(
            self.store, client,
            engagement_id=self.engagement_a.engagement_id,
        )
        self.assertEqual(len(result.items), 2)
        critical = result.items[0]
        self.assertEqual(critical.severity, Severity.CRITICAL)
        self.assertEqual(critical.next_review_step, "collect_evidence")
        self.assertEqual(critical.review_actions, (
            "collect_evidence", "author_remediation", "investigate_regression",
        ))
        self.assertFalse(critical.fix_verified)
        self.assertFalse(result.authorization_verified)
        self.assertFalse(result.retest_authorized)
        for secret in (
            finding.finding_id, finding.asset, finding.title, finding.impact,
            self.client_a.client_id, self.engagement_a.engagement_id,
        ):
            self.assertNotIn(secret, result.to_json())
        with self.store._connect() as con:
            after = [
                tuple(row) for row in con.execute(
                    "SELECT finding_id,client_id,engagement_id,remediation,"
                    "evidence_ids_json,retest_status FROM findings "
                    "ORDER BY finding_id",
                ).fetchall()
            ]
        self.assertEqual(after, before)

    def test_real_persisted_fixed_claim_and_missing_evidence_remains_unverified(self):
        finding = self.store.record_finding(
            self.operator,
            self.engagement_a.engagement_id,
            title="Private claimed fixed but no remediation",
            severity=Severity.CRITICAL,
            asset="lab://claimed-fixed",
            impact="never executed",
            remediation="Synthetic initial human-authored remediation",
            evidence_ids=(),
        )
        # DomainStore correctly refuses empty remediation at creation; emulate
        # a legacy/imported incomplete row in this disposable local database.
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET remediation='' WHERE finding_id=?",
                (finding.finding_id,),
            )
        self.store.set_retest_status(
            self.operator, finding.finding_id, RetestStatus.FIXED,
        )
        selected = self._rows(self.engagement_a.engagement_id)
        first = build_remediation_review_queue(
            selected,
            client_id=self.client_a.client_id,
            engagement_id=self.engagement_a.engagement_id,
        )
        item = first.items[0]
        self.assertEqual(item.severity, Severity.CRITICAL)
        self.assertEqual(item.review_actions, (
            "collect_evidence", "author_remediation", "independent_retest",
        ))
        self.assertFalse(first.evidence_verified)
        self.assertFalse(first.release_authorized)
        self.assertFalse(item.fix_verified)
        self.assertFalse(item.remediation_authorized)
        self.assertEqual(
            self.store.list_findings(
                self.operator, engagement_id=self.engagement_a.engagement_id,
            )[0].retest_status,
            RetestStatus.FIXED,
        )



if __name__ == "__main__":
    unittest.main()
