from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedEngagementOwnershipIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-engagement-owner", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Ownership Client A")
        self.client_b = self.store.create_client(self.operator, "Ownership Client B")
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client_a.client_id,
            "Execution resolver ownership integrity",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Ownership",
            "AUTH-OWNERSHIP-001",
            ScopeDefinition(
                assets=("app.ownership.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_engagement_client(self, client_id: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE engagements SET client_id=? WHERE engagement_id=?",
                (client_id, self.engagement.engagement_id),
            )

    def _ownership_pair(self) -> tuple[str, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT e.client_id AS engagement_client_id, "
                "g.client_id AS grant_client_id "
                "FROM engagements AS e "
                "JOIN authorization_grants AS g ON g.engagement_id=e.engagement_id "
                "WHERE e.engagement_id=? AND g.grant_id=?",
                (self.engagement.engagement_id, self.grant.grant_id),
            ).fetchone()
        assert row is not None
        return row["engagement_client_id"], row["grant_client_id"]

    def test_matching_durable_ownership_remains_executable(self) -> None:
        self.assertEqual(
            self._ownership_pair(),
            (self.client_a.client_id, self.client_a.client_id),
        )
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)

    def test_durable_engagement_owner_drift_fails_closed_without_rewrite(self) -> None:
        self._set_engagement_client(self.client_b.client_id)
        before = self._ownership_pair()
        self.assertEqual(
            before,
            (self.client_b.client_id, self.client_a.client_id),
            "fixture must represent a cross-tenant durable ownership mismatch",
        )

        self.assertIsNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "a grant must not remain executable after its engagement moves to another client",
        )
        self.assertEqual(
            self._ownership_pair(),
            before,
            "execution resolution must not repair or normalize durable tenant ownership",
        )

        self._set_engagement_client(self.client_a.client_id)
        self.assertIsNotNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "explicitly restoring canonical ownership should restore normal resolution",
        )


if __name__ == "__main__":
    unittest.main()
