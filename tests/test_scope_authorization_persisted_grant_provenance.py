from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedGrantProvenanceAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-provenance", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Grant Provenance Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Grant provenance"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Provenance",
            "AUTH-PROVENANCE-001",
            ScopeDefinition(
                assets=("app.provenance.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_persisted(self, column: str, value: str) -> None:
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {column}=? WHERE grant_id=?",
                (value, self.grant.grant_id),
            )

    def test_canonical_persisted_provenance_remains_executable(self) -> None:
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.approved_by, "CISO Provenance")
        self.assertEqual(live.reference, "AUTH-PROVENANCE-001")

    def test_blank_approved_by_is_non_executable(self) -> None:
        self._set_persisted("approved_by", "")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_whitespace_approved_by_is_non_executable(self) -> None:
        self._set_persisted("approved_by", "   ")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_blank_reference_is_non_executable(self) -> None:
        self._set_persisted("reference", "")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_whitespace_reference_is_non_executable(self) -> None:
        self._set_persisted("reference", "   ")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))


if __name__ == "__main__":
    unittest.main()
