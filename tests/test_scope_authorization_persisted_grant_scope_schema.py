from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedGrantScopeSchemaAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-scope-schema", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Scope Schema Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Scope schema"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Scope Schema",
            "AUTH-SCOPE-SCHEMA-001",
            ScopeDefinition(
                assets=(
                    "app.scope-schema.example",
                    "blocked.scope-schema.example",
                ),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
                excluded_assets=("blocked.scope-schema.example",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_persisted(self, column: str, value) -> None:
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {column}=? WHERE grant_id=?",
                (value, self.grant.grant_id),
            )

    def test_canonical_array_scope_remains_executable(self) -> None:
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(
            live.scope.assets,
            ("app.scope-schema.example", "blocked.scope-schema.example"),
        )
        self.assertEqual(live.scope.allowed_capabilities, ("web-baseline",))
        self.assertEqual(
            live.scope.excluded_assets, ("blocked.scope-schema.example",)
        )

    def test_malformed_assets_json_is_non_executable_without_exception(self) -> None:
        self._set_persisted("assets_json", "{not-json")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_object_shaped_assets_json_cannot_mint_asset_authority(self) -> None:
        self._set_persisted(
            "assets_json", '{"app.scope-schema.example": true}'
        )
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_malformed_allowed_capabilities_json_is_non_executable_without_exception(self) -> None:
        self._set_persisted("allowed_capabilities_json", "{not-json")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_object_shaped_capability_json_cannot_mint_capability_authority(self) -> None:
        self._set_persisted(
            "allowed_capabilities_json", '{"web-baseline": false}'
        )
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_malformed_excluded_assets_json_is_non_executable_without_exception(self) -> None:
        self._set_persisted("excluded_assets_json", "{not-json")
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_object_shaped_exclusions_cannot_drop_canonical_exclusion(self) -> None:
        self._set_persisted(
            "excluded_assets_json", '{"unrelated.scope-schema.example": false}'
        )
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))

    def test_invalid_persisted_max_risk_is_non_executable_without_exception(self) -> None:
        self._set_persisted("max_risk", 99)
        self.assertIsNone(self.store.resolve_authorization_for_execution(self.grant))


if __name__ == "__main__":
    unittest.main()
