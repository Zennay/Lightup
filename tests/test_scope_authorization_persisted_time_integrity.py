from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedGrantTemporalIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-temporal", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Temporal Integrity Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Temporal integrity"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Temporal",
            "AUTH-TEMPORAL-001",
            ScopeDefinition(
                assets=("app.temporal.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_persisted(self, column: str, value: str | None) -> None:
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {column}=? WHERE grant_id=?",
                (value, self.grant.grant_id),
            )

    def test_canonical_aware_window_remains_executable(self) -> None:
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)

    def test_offsetless_valid_from_fails_closed_without_exception(self) -> None:
        self._set_persisted("valid_from", "2026-10-07T00:00:00")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_malformed_valid_until_fails_closed_without_exception(self) -> None:
        self._set_persisted("valid_until", "not-a-timestamp")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_offsetless_revocation_time_fails_closed_without_exception(self) -> None:
        self._set_persisted("revoked_at", "2026-10-07T00:00:00")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))


if __name__ == "__main__":
    unittest.main()
