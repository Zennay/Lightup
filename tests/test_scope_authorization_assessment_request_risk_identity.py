from __future__ import annotations

import tempfile
import unittest
from enum import IntEnum
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class ForeignRisk(IntEnum):
    STANDARD = int(RiskLevel.STANDARD)


class AssessmentRequestRiskIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-risk-type", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Risk Type Client")
        self.client_ctx = AccessContext(
            "client-risk-type",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )

    def _submit(self, requested_risk):
        return self.store.submit_assessment_request(
            self.client_ctx,
            ("app.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk,
        )

    def test_canonical_risk_level_round_trips(self):
        request = self._submit(RiskLevel.STANDARD)

        self.assertIs(request.requested_risk, RiskLevel.STANDARD)
        persisted = self.store.get_assessment_request(
            self.client_ctx,
            request.request_id,
        )
        self.assertIs(persisted.requested_risk, RiskLevel.STANDARD)

    def test_noncanonical_integer_like_risks_fail_before_persistence(self):
        invalid_values = (
            True,
            int(RiskLevel.STANDARD),
            ForeignRisk.STANDARD,
        )

        for requested_risk in invalid_values:
            with self.subTest(
                value=requested_risk,
                value_type=type(requested_risk).__name__,
            ):
                before = self.store.list_assessment_requests(self.client_ctx)
                with self.assertRaises((TypeError, ValueError)):
                    self._submit(requested_risk)
                self.assertEqual(
                    self.store.list_assessment_requests(self.client_ctx),
                    before,
                )


if __name__ == "__main__":
    unittest.main()
