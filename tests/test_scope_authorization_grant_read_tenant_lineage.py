from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class GrantReadTenantLineageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")
        self.ctx_a = AccessContext(
            "user-a", Role.CLIENT_ADMIN, self.client_a.client_id
        )
        self.engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Q4"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Acme",
            "AUTH-2026-001",
            ScopeDefinition(
                assets=("app.acme.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(minutes=5),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _row(self) -> dict[str, object]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT * FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return dict(row)

    def _corrupt_client_lineage(self) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
                (self.client_b.client_id, self.grant.grant_id),
            )

    def test_canonical_grant_remains_readable_and_current(self) -> None:
        grants = self.store.list_authorization_grants(
            self.ctx_a, self.engagement.engagement_id
        )
        self.assertEqual([grant.grant_id for grant in grants], [self.grant.grant_id])

        current = self.store.get_current_grant(
            self.ctx_a, self.engagement.engagement_id
        )
        self.assertIsNotNone(current)
        self.assertEqual(current.grant_id, self.grant.grant_id)

    def test_list_filters_cross_tenant_incoherent_grant(self) -> None:
        self._corrupt_client_lineage()
        before = self._row()

        self.assertEqual(
            self.store.list_authorization_grants(
                self.ctx_a, self.engagement.engagement_id
            ),
            [],
        )

        self.assertEqual(self._row(), before)

    def test_current_grant_does_not_surface_cross_tenant_incoherent_row(self) -> None:
        self._corrupt_client_lineage()
        before = self._row()

        self.assertIsNone(
            self.store.get_current_grant(
                self.ctx_a, self.engagement.engagement_id
            )
        )

        self.assertEqual(self._row(), before)


if __name__ == "__main__":
    unittest.main()
