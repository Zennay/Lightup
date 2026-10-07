from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, RequestStatus, Role
from lightup.engagements import AssessmentMode, RiskLevel


class PersistedAssessmentRequestDecisionProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-decision-read", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Decision Read Client")
        self.client_ctx = AccessContext(
            "client-decision-read",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )

    def _request(self):
        return self.store.submit_assessment_request(
            self.client_ctx,
            ("app.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )

    def _set_decision_state(
        self,
        request_id: str,
        status: str,
        decided_by: object,
        decided_at: object,
    ) -> tuple[object, ...]:
        with self.store._connect() as con:
            con.execute(
                "UPDATE assessment_requests "
                "SET status=?, decided_by=?, decided_at=? WHERE request_id=?",
                (status, decided_by, decided_at, request_id),
            )
            row = con.execute(
                "SELECT status, decided_by, decided_at "
                "FROM assessment_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def _decision_state(self, request_id: str) -> tuple[object, ...]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT status, decided_by, decided_at "
                "FROM assessment_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def test_canonical_open_and_decided_rows_round_trip(self):
        submitted = self._request()
        reloaded = self.store.get_assessment_request(
            self.client_ctx,
            submitted.request_id,
        )
        self.assertIs(reloaded.status, RequestStatus.SUBMITTED)
        self.assertIsNone(reloaded.decided_by)
        self.assertIsNone(reloaded.decided_at)

        approved = self.store.review_assessment_request(
            self.operator,
            submitted.request_id,
            True,
        )
        self.assertIs(approved.status, RequestStatus.APPROVED)
        self.assertEqual(approved.decided_by, self.operator.user_id)
        self.assertIsNotNone(approved.decided_at)
        decided_at = datetime.fromisoformat(approved.decided_at)
        self.assertIsNotNone(decided_at.tzinfo)

    def test_corrupt_decision_provenance_fails_closed_without_repair(self):
        aware = datetime.now(timezone.utc).isoformat()
        corrupt_states = (
            (RequestStatus.APPROVED.value, None, None),
            (RequestStatus.REJECTED.value, "op-decision-read", None),
            (RequestStatus.APPROVED.value, None, aware),
            (RequestStatus.SUBMITTED.value, "op-decision-read", aware),
            (RequestStatus.UNDER_REVIEW.value, "op-decision-read", aware),
            (RequestStatus.APPROVED.value, " ", aware),
            (RequestStatus.APPROVED.value, "op-decision-read", "not-a-time"),
            (
                RequestStatus.APPROVED.value,
                "op-decision-read",
                "2026-10-07T20:00:00",
            ),
        )

        for status, decided_by, decided_at in corrupt_states:
            with self.subTest(
                status=status,
                decided_by=decided_by,
                decided_at=decided_at,
            ):
                request = self._request()
                stored = self._set_decision_state(
                    request.request_id,
                    status,
                    decided_by,
                    decided_at,
                )

                with self.assertRaises((TypeError, ValueError)):
                    self.store.get_assessment_request(
                        self.client_ctx,
                        request.request_id,
                    )

                self.assertEqual(
                    self._decision_state(request.request_id),
                    stored,
                )


if __name__ == "__main__":
    unittest.main()
