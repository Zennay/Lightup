from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class ScopeDefinitionMutableInputAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-scope-mutable", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "ScopeDefinition Mutable Input Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Immutable durable scope definition",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(hours=1)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _record(self, scope: ScopeDefinition):
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Immutable Scope",
            "AUTH-IMMUTABLE-SCOPE-001",
            scope,
            self.valid_from,
            self.valid_until,
        )

    def _durable_scope_state(self) -> tuple[str, str, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT assets_json,excluded_assets_json,allowed_capabilities_json "
                "FROM authorization_grants WHERE engagement_id=? "
                "ORDER BY created_at DESC LIMIT 1",
                (self.engagement.engagement_id,),
            ).fetchone()
        assert row is not None
        return (
            row["assets_json"],
            row["excluded_assets_json"],
            row["allowed_capabilities_json"],
        )

    @staticmethod
    def _construct_or_accept_rejection(**kwargs: Any) -> ScopeDefinition | None:
        try:
            return ScopeDefinition(**kwargs)
        except (TypeError, ValueError):
            # Rejecting mutable collection inputs at construction is also
            # a valid fail-closed implementation of this contract.
            return None

    def test_canonical_tuple_scope_remains_stable(self) -> None:
        scope = ScopeDefinition(
            assets=("app.immutable-scope.example",),
            excluded_assets=("admin.immutable-scope.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        grant = self._record(scope)
        before = self._durable_scope_state()

        self.assertFalse(grant.scope.allows_asset("other.immutable-scope.example"))
        self.assertFalse(grant.scope.allows_asset("admin.immutable-scope.example"))
        self.assertFalse(grant.scope.allows_capability("future-capability"))
        self.assertEqual(self._durable_scope_state(), before)

    def test_caller_owned_asset_list_cannot_widen_issued_grant(self) -> None:
        assets = ["app.immutable-scope.example"]
        scope = self._construct_or_accept_rejection(
            assets=assets,
            excluded_assets=(),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        if scope is None:
            return

        grant = self._record(scope)
        before = self._durable_scope_state()
        self.assertFalse(grant.scope.allows_asset("new.immutable-scope.example"))

        assets.append("new.immutable-scope.example")

        self.assertFalse(
            grant.scope.allows_asset("new.immutable-scope.example"),
            "caller-owned mutation must not widen an already-issued grant",
        )
        self.assertEqual(
            self._durable_scope_state(),
            before,
            "caller-owned mutation must not alter the persisted scope snapshot",
        )

    def test_caller_owned_exclusion_list_cannot_remove_denial(self) -> None:
        exclusions = ["admin.immutable-scope.example"]
        scope = self._construct_or_accept_rejection(
            assets=("admin.immutable-scope.example",),
            excluded_assets=exclusions,
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        if scope is None:
            return

        grant = self._record(scope)
        before = self._durable_scope_state()
        self.assertFalse(grant.scope.allows_asset("admin.immutable-scope.example"))

        exclusions.clear()

        self.assertFalse(
            grant.scope.allows_asset("admin.immutable-scope.example"),
            "caller-owned mutation must not erase an issued exclusion",
        )
        self.assertEqual(self._durable_scope_state(), before)

    def test_caller_owned_capability_list_cannot_widen_issued_grant(self) -> None:
        capabilities = ["web-baseline"]
        scope = self._construct_or_accept_rejection(
            assets=("app.immutable-scope.example",),
            excluded_assets=(),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=capabilities,
        )
        if scope is None:
            return

        grant = self._record(scope)
        before = self._durable_scope_state()
        self.assertFalse(grant.scope.allows_capability("future-capability"))

        capabilities.append("future-capability")

        self.assertFalse(
            grant.scope.allows_capability("future-capability"),
            "caller-owned mutation must not widen issued capability authority",
        )
        self.assertEqual(self._durable_scope_state(), before)


if __name__ == "__main__":
    unittest.main()
