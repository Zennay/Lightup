from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel


class _StatefulJustification(str):
    """Looks safe on the first strip() read, then changes its durable value."""

    def __new__(cls) -> "_StatefulJustification":
        value = super().__new__(cls, "reviewed escalation rationale")
        value._strip_calls = 0
        return value

    def strip(self, chars=None):  # type: ignore[override]
        self._strip_calls += 1
        if self._strip_calls == 1:
            return "reviewed escalation rationale"
        return ""


class _DuckJustification:
    def strip(self, chars=None):
        return "duck-typed rationale"


class RiskElevationJustificationAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_ctx = AccessContext(
            "client-admin-1", Role.CLIENT_ADMIN, self.client.client_id
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Risk justification boundary"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _approvals(self):
        return self.store.list_risk_approvals(
            self.client_ctx, self.engagement.engagement_id
        )

    def test_canonical_builtin_justification_is_trimmed_once_for_persistence(self) -> None:
        approval = self.store.request_risk_elevation(
            self.client_ctx,
            self.engagement.engagement_id,
            RiskLevel.ELEVATED,
            "  reviewed escalation rationale  ",
        )

        self.assertEqual(approval.justification, "reviewed escalation rationale")
        persisted = self._approvals()
        self.assertEqual(len(persisted), 1)
        self.assertEqual(
            persisted[0].justification,
            "reviewed escalation rationale",
        )

    def test_stateful_str_subclass_cannot_change_justification_after_validation(self) -> None:
        justification = _StatefulJustification()

        with self.assertRaises(ValueError):
            self.store.request_risk_elevation(
                self.client_ctx,
                self.engagement.engagement_id,
                RiskLevel.ELEVATED,
                justification,
            )

        self.assertEqual(self._approvals(), [])

    def test_strip_duck_is_rejected_before_persistence(self) -> None:
        with self.assertRaises(ValueError):
            self.store.request_risk_elevation(
                self.client_ctx,
                self.engagement.engagement_id,
                RiskLevel.ELEVATED,
                _DuckJustification(),  # type: ignore[arg-type]
            )

        self.assertEqual(self._approvals(), [])


if __name__ == "__main__":
    unittest.main()
