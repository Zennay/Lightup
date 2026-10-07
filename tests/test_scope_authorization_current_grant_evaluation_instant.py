from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class CurrentGrantEvaluationInstantTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-current-now", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Current Now Client")
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Current now",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            approved_by="security-owner@example.test",
            reference="AUTH-CURRENT-NOW",
            scope=ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )

    def _raw_grant(self) -> tuple[object, ...]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT grant_id,valid_from,valid_until,recurring_retest_allowed,"
                "revoked_at,revoked_by,revocation_reason "
                "FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def test_none_omission_and_exact_aware_datetime_remain_valid(self):
        implicit = self.store.get_current_grant(
            self.operator,
            self.engagement.engagement_id,
        )
        self.assertIsNotNone(implicit)
        self.assertEqual(implicit.grant_id, self.grant.grant_id)

        explicit = self.store.get_current_grant(
            self.operator,
            self.engagement.engagement_id,
            now=datetime.now(timezone.utc),
        )
        self.assertIsNotNone(explicit)
        self.assertEqual(explicit.grant_id, self.grant.grant_id)

    def test_explicit_falsy_non_datetime_values_fail_without_substitution(self):
        malformed = (
            False,
            0,
            0.0,
            "",
            b"",
            [],
        )

        for now in malformed:
            with self.subTest(now=now, value_type=type(now).__name__):
                before = self._raw_grant()

                with self.assertRaises((TypeError, ValueError)):
                    self.store.get_current_grant(
                        self.operator,
                        self.engagement.engagement_id,
                        now=now,
                    )

                self.assertEqual(self._raw_grant(), before)


if __name__ == "__main__":
    unittest.main()
