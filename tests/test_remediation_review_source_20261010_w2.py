"""Integration proof for opt-in, read-only DomainStore advisory adapter."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.models import RetestStatus, Severity
from lightup.remediation_review_source import read_remediation_review_queue


class RemediationReviewSourceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "synthetic.sqlite")
        self.operator = AccessContext("op-review-reader", Role.OPERATOR)
        self.first = self.store.create_client(self.operator, "Synthetic client first")
        self.second = self.store.create_client(self.operator, "Synthetic client second")
        self.eng_first = self.store.create_engagement(
            self.operator, self.first.client_id, "Synthetic engagement first"
        )
        self.eng_second = self.store.create_engagement(
            self.operator, self.second.client_id, "Synthetic engagement second"
        )
        self.row_first = self.store.record_finding(
            self.operator, self.eng_first.engagement_id,
            title="Confidential first finding", severity=Severity.MEDIUM,
            asset="lab://first", impact="private first",
            remediation="Secure the synthetic fixture",
            evidence_ids=("synthetic-ref-first",),
        )
        self.row_second = self.store.record_finding(
            self.operator, self.eng_second.engagement_id,
            title="Confidential second finding", severity=Severity.HIGH,
            asset="lab://second", impact="private second",
            remediation="Secure second synthetic fixture",
            evidence_ids=("synthetic-ref-second",),
        )
        self.client_ctx = AccessContext(
            "synthetic-client-member", Role.CLIENT_MEMBER, self.first.client_id
        )

    def _read(self, ctx=None, engagement_id=None):
        return read_remediation_review_queue(
            self.store, ctx or self.client_ctx,
            engagement_id=engagement_id or self.eng_first.engagement_id,
        )

    def _raw(self):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT client_id, engagement_id, evidence_ids_json, retest_status "
                "FROM findings WHERE finding_id=?", (self.row_first.finding_id,)
            ).fetchone()
            return tuple(row)

    def _corrupt(self, column, value):
        assert column in {"evidence_ids_json", "client_id"}
        with self.store._connect() as con:
            con.execute(
                f"UPDATE findings SET {column}=? WHERE finding_id=?",
                (value, self.row_first.finding_id),
            )

    def test_client_session_context_reads_only_its_own_engagement(self):
        result = self._read()
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].referenced_evidence_count, 1)
        self.assertFalse(result.remediation_authorized)
        self.assertFalse(result.evidence_verified)
        for private in (
            self.first.client_id, self.eng_first.engagement_id,
            self.row_first.title, self.row_first.asset,
            "synthetic-ref-first", "synthetic-ref-second",
        ):
            self.assertNotIn(private, result.to_json())

    def test_operator_must_still_choose_a_single_engagement(self):
        first = self._read(ctx=self.operator)
        second = self._read(
            ctx=self.operator, engagement_id=self.eng_second.engagement_id
        )
        self.assertEqual(len(first.items), 1)
        self.assertEqual(len(second.items), 1)
        self.assertNotEqual(first.digest_sha256, second.digest_sha256)

    def test_cross_tenant_read_preserves_domain_access_denial(self):
        with self.assertRaises(TenantIsolationError):
            self._read(engagement_id=self.eng_second.engagement_id)

    def test_missing_engagement_cannot_trigger_global_operator_findings_read(self):
        for invalid in ("", "  ", [], 1, None, b"valid",
                        "bad\nselector", "e" * 129):
            with self.subTest(invalid=repr(invalid)[:30]):
                with self.assertRaises(ValueError):
                    read_remediation_review_queue(
                        self.store, self.operator, engagement_id=invalid
                    )

    def test_malformed_persisted_json_rejected_with_generic_error_and_zero_write(self):
        for raw in ('["partial"', "null", "123", '{"bad":true}'):
            with self.subTest(raw=raw):
                self._corrupt("evidence_ids_json", raw)
                before = self._raw()
                with self.assertRaises(ValueError) as caught:
                    self._read()
                self.assertEqual(
                    str(caught.exception), "remediation evidence read integrity invalid"
                )
                self.assertEqual(self._raw(), before)

    def test_corrupt_cross_tenant_finding_owner_row_fails_closed_without_write(self):
        self._corrupt("client_id", self.second.client_id)
        before = self._raw()
        with self.assertRaisesRegex(
            ValueError, "^remediation evidence read integrity invalid$"
        ):
            self._read()
        self.assertEqual(self._raw(), before)

    def test_repeated_selection_is_read_only_and_deterministic(self):
        before = self._raw()
        first = self._read()
        second = self._read()
        self.assertEqual(first, second)
        self.assertEqual(self._raw(), before)

    def test_retest_claim_never_authorizes_verified_remediation(self):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET retest_status=? WHERE finding_id=?",
                (RetestStatus.FIXED.value, self.row_first.finding_id),
            )
        before = self._raw()
        review = self._read()
        self.assertEqual(review.items[0].next_review_step, "independent_retest")
        self.assertFalse(review.items[0].fix_verified)
        self.assertFalse(review.retest_authorized)
        self.assertEqual(self._raw(), before)

    def test_rejects_wrong_context_or_store_class_without_effect(self):
        before = self._raw()
        for store, ctx in ((object(), self.client_ctx),
                           (self.store, object()),
                           (self.store, None)):
            with self.subTest(store=type(store).__name__, ctx=type(ctx).__name__):
                with self.assertRaisesRegex(ValueError, "invalid remediation review read context"):
                    read_remediation_review_queue(
                        store, ctx, engagement_id=self.eng_first.engagement_id,
                    )
        self.assertEqual(self._raw(), before)


if __name__ == "__main__":
    unittest.main()
