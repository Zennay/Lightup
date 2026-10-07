from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class _SwitchingSqliteRequestId:
    def __init__(self, *values: str) -> None:
        self.values = values
        self.calls = 0

    def __conform__(self, protocol):
        if protocol is not sqlite3.PrepareProtocol:
            return None
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        return value


class AssessmentReviewIdentityBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-assessment-review-id", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Assessment Review Identity Client"
        )
        self.client_ctx = AccessContext(
            "client-assessment-review-id",
            Role.CLIENT_MEMBER,
            self.client.client_id,
        )
        self.request_a = self._submit("a.review-id.example")
        self.request_b = self._submit("b.review-id.example")

        # Simulate producer-impossible/legacy durable state that #133 requires
        # decision-time approval to reject.
        with self.store._connect() as con:
            con.execute(
                "UPDATE assessment_requests SET requested_risk=? WHERE request_id=?",
                (int(RiskLevel.DESTRUCTIVE_LAB_ONLY), self.request_b.request_id),
            )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _submit(self, asset: str):
        return self.store.submit_assessment_request(
            self.client_ctx,
            requested_assets=(asset,),
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=RiskLevel.STANDARD,
            notes="review identity binding",
        )

    def _rows(self) -> list[tuple[str, int, str]]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT request_id,requested_risk,status "
                "FROM assessment_requests ORDER BY created_at,request_id"
            ).fetchall()
        return [
            (row["request_id"], row["requested_risk"], row["status"])
            for row in rows
        ]

    def _row(self, request_id: str) -> tuple[int, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT requested_risk,status FROM assessment_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        assert row is not None
        return row["requested_risk"], row["status"]

    def test_canonical_safe_request_approval_targets_that_exact_record(self) -> None:
        reviewed = self.store.review_assessment_request(
            self.operator, self.request_a.request_id, True
        )
        self.assertEqual(reviewed.request_id, self.request_a.request_id)
        self.assertEqual(reviewed.status.value, "approved")
        self.assertEqual(self._row(self.request_a.request_id)[1], "approved")
        self.assertEqual(
            self._row(self.request_b.request_id),
            (int(RiskLevel.DESTRUCTIVE_LAB_ONLY), "submitted"),
        )

    def test_exact_destructive_legacy_request_remains_denied(self) -> None:
        before = self._rows()
        with self.assertRaises(ValueError):
            self.store.review_assessment_request(
                self.operator, self.request_b.request_id, True
            )
        self.assertEqual(self._rows(), before)

    def test_switching_request_identity_cannot_validate_a_and_approve_b(self) -> None:
        request_id = _SwitchingSqliteRequestId(
            self.request_a.request_id,
            self.request_b.request_id,
            self.request_b.request_id,
        )
        before = self._rows()

        with self.assertRaises(
            ValueError,
            msg="review must reject a non-canonical request identity before SQLite binding",
        ):
            self.store.review_assessment_request(self.operator, request_id, True)

        self.assertEqual(
            request_id.calls,
            0,
            "request identity must be canonical before any safety read or mutation",
        )
        self.assertEqual(
            self._rows(),
            before,
            "identity rejection must leave every assessment request unchanged",
        )


if __name__ == "__main__":
    unittest.main()
