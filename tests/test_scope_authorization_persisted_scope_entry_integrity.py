from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class PersistedScopeEntryIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-scope-entry-integrity", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Persisted Scope Entry Integrity Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Execution resolver persisted scope entry integrity",
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Scope Entry",
            "AUTH-SCOPE-ENTRY-001",
            ScopeDefinition(
                assets=("app.scope-entry.example",),
                excluded_assets=("admin.scope-entry.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            now - timedelta(hours=1),
            now + timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _set_scope_field(self, field: str, value: Any) -> None:
        if field not in {
            "assets_json",
            "excluded_assets_json",
            "allowed_capabilities_json",
        }:
            raise AssertionError(f"unsupported scope field {field!r}")
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {field}=? WHERE grant_id=?",
                (json.dumps(value), self.grant.grant_id),
            )

    def _scope_state(self) -> tuple[str, str, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT assets_json,excluded_assets_json,allowed_capabilities_json "
                "FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        assert row is not None
        return (
            row["assets_json"],
            row["excluded_assets_json"],
            row["allowed_capabilities_json"],
        )

    def _assert_corrupt_scope_is_non_executable_without_rewrite(
        self, field: str, value: Any
    ) -> None:
        self._set_scope_field(field, value)
        before = self._scope_state()

        try:
            resolved = self.store.resolve_authorization_for_execution(self.grant)
        except Exception as exc:  # acceptance requires a controlled fail-closed result
            self.fail(
                f"corrupt persisted {field} leaked {type(exc).__name__}: {exc}"
            )

        self.assertIsNone(
            resolved,
            f"producer-impossible persisted {field} must not retain execution authority",
        )
        self.assertEqual(
            self._scope_state(),
            before,
            "execution resolution must reject rather than normalize durable scope state",
        )

    def test_canonical_scope_entries_remain_executable(self) -> None:
        before = self._scope_state()
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)
        self.assertEqual(self._scope_state(), before)

    def test_empty_persisted_asset_allowlist_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "assets_json", []
        )

    def test_blank_persisted_asset_identity_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "assets_json", ["   "]
        )

    def test_non_string_persisted_asset_identity_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "assets_json", [123]
        )

    def test_blank_persisted_exclusion_identity_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "excluded_assets_json", ["\t"]
        )

    def test_non_string_persisted_exclusion_identity_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "excluded_assets_json", [False]
        )

    def test_blank_persisted_capability_identity_fails_closed(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "allowed_capabilities_json", [" "]
        )

    def test_non_string_persisted_capability_identity_fails_closed_without_exception(self) -> None:
        self._assert_corrupt_scope_is_non_executable_without_rewrite(
            "allowed_capabilities_json", [{"web-baseline": True}]
        )


if __name__ == "__main__":
    unittest.main()
