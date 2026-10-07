from __future__ import annotations

import tempfile
import unittest
from enum import Enum
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class ForeignAssessmentMode(str, Enum):
    AUTHORIZED_ASSESSMENT = AssessmentMode.AUTHORIZED_ASSESSMENT.value


class DuckAssessmentMode:
    value = AssessmentMode.AUTHORIZED_ASSESSMENT.value


class AssessmentRequestModeIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-mode-type", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Mode Type Client")
        self.client_ctx = AccessContext(
            "client-mode-type",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )

    def _submit(self, requested_mode):
        return self.store.submit_assessment_request(
            self.client_ctx,
            ("app.example.test",),
            requested_mode,
            RiskLevel.STANDARD,
        )

    def test_canonical_assessment_mode_round_trips(self):
        request = self._submit(AssessmentMode.AUTHORIZED_ASSESSMENT)

        self.assertIs(
            request.requested_mode,
            AssessmentMode.AUTHORIZED_ASSESSMENT,
        )
        persisted = self.store.get_assessment_request(
            self.client_ctx,
            request.request_id,
        )
        self.assertIs(
            persisted.requested_mode,
            AssessmentMode.AUTHORIZED_ASSESSMENT,
        )

    def test_noncanonical_mode_objects_fail_before_persistence(self):
        invalid_values = (
            ForeignAssessmentMode.AUTHORIZED_ASSESSMENT,
            DuckAssessmentMode(),
        )

        for requested_mode in invalid_values:
            with self.subTest(value_type=type(requested_mode).__name__):
                before = self.store.list_assessment_requests(self.client_ctx)
                with self.assertRaises((TypeError, ValueError)):
                    self._submit(requested_mode)
                self.assertEqual(
                    self.store.list_assessment_requests(self.client_ctx),
                    before,
                )


if __name__ == "__main__":
    unittest.main()
