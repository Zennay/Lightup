from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class _SwitchingSqliteIdentity:
    """SQLite-adaptable object that changes the bound TEXT identity per use."""

    def __init__(self, *values: str) -> None:
        self.values = values
        self.calls = 0

    def __conform__(self, protocol):
        if protocol is not sqlite3.PrepareProtocol:
            return None
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        return value


class GrantEngagementIdentityIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-grant-engagement-id", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Grant Identity Client A")
        self.client_b = self.store.create_client(self.operator, "Grant Identity Client B")
        self.engagement_a = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Engagement A"
        )
        self.engagement_b = self.store.create_engagement(
            self.operator, self.client_b.client_id, "Engagement B"
        )
        self.scope = ScopeDefinition(
            assets=("app.grant-identity.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(hours=1)
        self.valid_until = now + timedelta(hours=1)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant_rows(self) -> list[tuple[str, str]]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT client_id,engagement_id FROM authorization_grants ORDER BY created_at"
            ).fetchall()
        return [(row["client_id"], row["engagement_id"]) for row in rows]

    def _record(self, engagement_id):
        return self.store.record_authorization_grant(
            self.operator,
            engagement_id,
            "CISO Grant Identity",
            "AUTH-GRANT-ID-001",
            self.scope,
            self.valid_from,
            self.valid_until,
        )

    def test_exact_builtin_engagement_identity_remains_canonical(self) -> None:
        grant = self._record(self.engagement_a.engagement_id)
        self.assertEqual(grant.engagement_id, self.engagement_a.engagement_id)
        self.assertEqual(grant.client_id, self.client_a.client_id)
        self.assertEqual(
            self._grant_rows(),
            [(self.client_a.client_id, self.engagement_a.engagement_id)],
        )

    def test_sqlite_adaptable_identity_cannot_switch_lookup_and_persistence(self) -> None:
        identity = _SwitchingSqliteIdentity(
            self.engagement_a.engagement_id,
            self.engagement_b.engagement_id,
        )
        before = self._grant_rows()

        with self.assertRaises(
            ValueError,
            msg="non-canonical engagement identity must fail before SQLite adaptation",
        ):
            self._record(identity)

        self.assertEqual(
            identity.calls,
            0,
            "validation must reject a non-string engagement identity before SQLite binds it",
        )
        self.assertEqual(
            self._grant_rows(),
            before,
            "rejected engagement identity must not mint a durable grant row",
        )

    def test_even_stable_sqlite_adapter_is_not_a_canonical_engagement_identity(self) -> None:
        identity = _SwitchingSqliteIdentity(
            self.engagement_a.engagement_id,
            self.engagement_a.engagement_id,
        )
        before = self._grant_rows()

        with self.assertRaises(ValueError):
            self._record(identity)

        self.assertEqual(identity.calls, 0)
        self.assertEqual(self._grant_rows(), before)


if __name__ == "__main__":
    unittest.main()
