from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedRevocationCoherenceAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-revocation-coherence", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Revocation Coherence Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Execution resolver revocation coherence",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Revocation",
            "AUTH-REVOCATION-001",
            ScopeDefinition(
                assets=("app.revocation.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_revocation_state(
        self,
        *,
        revoked_at: str | None,
        revoked_by: str | None,
        revocation_reason: str | None,
    ) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE authorization_grants "
                "SET revoked_at=?, revoked_by=?, revocation_reason=? "
                "WHERE grant_id=?",
                (
                    revoked_at,
                    revoked_by,
                    revocation_reason,
                    self.grant.grant_id,
                ),
            )

    def _revocation_state(self) -> tuple[str | None, str | None, str | None]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT revoked_at,revoked_by,revocation_reason "
                "FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        assert row is not None
        return row["revoked_at"], row["revoked_by"], row["revocation_reason"]

    def _assert_partial_state_is_non_executable_without_rewrite(
        self,
        *,
        revoked_by: str | None,
        revocation_reason: str | None,
    ) -> None:
        self._set_revocation_state(
            revoked_at=None,
            revoked_by=revoked_by,
            revocation_reason=revocation_reason,
        )
        before = self._revocation_state()

        self.assertIsNone(
            self.store.resolve_authorization_for_execution(self.grant),
            "partial durable revocation metadata must never regain execution authority",
        )
        self.assertEqual(
            self._revocation_state(),
            before,
            "execution resolution must reject rather than normalize durable corruption",
        )

    def test_canonical_unrevoked_state_remains_executable(self) -> None:
        self.assertEqual(self._revocation_state(), (None, None, None))
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)

    def test_canonical_revoked_state_remains_non_executable(self) -> None:
        revoked_at = datetime.now(timezone.utc).isoformat()
        self._set_revocation_state(
            revoked_at=revoked_at,
            revoked_by="op-revoker",
            revocation_reason="authorization withdrawn",
        )
        before = self._revocation_state()

        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))
        self.assertEqual(self._revocation_state(), before)

    def test_actor_and_reason_without_revocation_timestamp_fail_closed(self) -> None:
        self._assert_partial_state_is_non_executable_without_rewrite(
            revoked_by="op-revoker",
            revocation_reason="authorization withdrawn",
        )

    def test_actor_without_revocation_timestamp_fails_closed(self) -> None:
        self._assert_partial_state_is_non_executable_without_rewrite(
            revoked_by="op-revoker",
            revocation_reason=None,
        )

    def test_reason_without_revocation_timestamp_fails_closed(self) -> None:
        self._assert_partial_state_is_non_executable_without_rewrite(
            revoked_by=None,
            revocation_reason="authorization withdrawn",
        )


if __name__ == "__main__":
    unittest.main()
