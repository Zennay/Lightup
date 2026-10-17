"""#648: original ScopeDefinition must isolate caller-owned mutable collections.

Acceptance-only: no source-owner code changes, no real authority, no target I/O.
A future implementation may snapshot exact mutable lists to tuples OR reject
non-tuple construction outright. Six deliberately open original-source REDs
become mandatory under LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX=1.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


_SOURCE_CONTRACT = (
    (lambda method: method)
    if os.environ.get("LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX") == "1"
    else unittest.expectedFailure
)


class DurableCollectionIsolationAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope648_")
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "fictional.sqlite3")
        self.op = AccessContext("synthetic-operator", Role.OPERATOR)
        client = self.store.create_client(self.op, "Fictional Client #648")
        self.engagement = self.store.create_engagement(
            self.op, client.client_id, "No real client/approval"
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=1)
        self.valid_until = now + timedelta(hours=1)

    def scope(self, *, assets=None, excluded=None, capabilities=None):
        return ScopeDefinition(
            assets=("in.invalid", "excluded.invalid") if assets is None else assets,
            excluded_assets=("excluded.invalid",) if excluded is None else excluded,
            allowed_capabilities=("web-baseline",) if capabilities is None else capabilities,
            max_risk=RiskLevel.STANDARD,
        )

    def issue(self, scope):
        return self.store.record_authorization_grant(
            self.op, self.engagement.engagement_id,
            "Synthetic CISO", "SYNTHETIC-DOES-NOT-GRANT-AUTHORITY",
            scope, self.valid_from, self.valid_until,
        )

    def persisted(self):
        with closing(sqlite3.connect(self.store.path)) as con:
            return con.execute(
                "SELECT assets_json,excluded_assets_json,allowed_capabilities_json,"
                "max_risk FROM authorization_grants WHERE engagement_id=? "
                "ORDER BY grant_id", (self.engagement.engagement_id,)
            ).fetchall()

    @staticmethod
    def maybe_create(factory):
        # Both future source-owner policies are valid:
        # reject mutable collections at construction or snapshot them safely.
        try:
            return factory()
        except (TypeError, ValueError):
            return None

    def test_canonical_tuple_scope_remains_stable(self):
        scope = self.scope()
        self.assertIs(type(scope.assets), tuple)
        self.assertIs(type(scope.excluded_assets), tuple)
        self.assertIs(type(scope.allowed_capabilities), tuple)
        self.assertTrue(scope.allows_asset("in.invalid"))
        self.assertFalse(scope.allows_asset("excluded.invalid"))
        self.assertFalse(scope.allows_asset("outside.invalid"))
        self.assertTrue(scope.allows_capability("web-baseline"))
        self.assertFalse(scope.allows_capability("api-baseline"))
        self.assertEqual(self.persisted(), [])

    def test_canonical_tuple_grant_persists_without_widening(self):
        grant = self.issue(self.scope())
        self.assertTrue(grant.scope.allows_asset("in.invalid"))
        self.assertFalse(grant.scope.allows_asset("excluded.invalid"))
        self.assertFalse(grant.scope.allows_capability("api-baseline"))
        self.assertEqual(self.persisted(), [
            ('["in.invalid", "excluded.invalid"]', '["excluded.invalid"]',
             '["web-baseline"]', int(RiskLevel.STANDARD))
        ])

    def test_rejected_empty_assets_list_does_not_insert_row(self):
        # Future constructor rejection and current issuance rejection both deny.
        with self.assertRaises((TypeError, ValueError)):
            scope = self.scope(assets=[])
            self.issue(scope)
        self.assertEqual(self.persisted(), [])

    @_SOURCE_CONTRACT
    def test_source_red_asset_list_must_snapshot_or_reject(self):
        assets = ["in.invalid", "excluded.invalid"]
        scope = self.maybe_create(lambda: self.scope(assets=assets))
        if scope is not None:
            self.assertIs(type(scope.assets), tuple)
            assets.append("outside.invalid")
            self.assertFalse(scope.allows_asset("outside.invalid"))
        self.assertEqual(self.persisted(), [])

    @_SOURCE_CONTRACT
    def test_source_red_excluded_list_must_snapshot_or_reject(self):
        excluded = ["excluded.invalid"]
        scope = self.maybe_create(lambda: self.scope(excluded=excluded))
        if scope is not None:
            self.assertIs(type(scope.excluded_assets), tuple)
            excluded.clear()
            self.assertFalse(scope.allows_asset("excluded.invalid"))
        self.assertEqual(self.persisted(), [])

    @_SOURCE_CONTRACT
    def test_source_red_capability_list_must_snapshot_or_reject(self):
        capabilities = ["web-baseline"]
        scope = self.maybe_create(lambda: self.scope(capabilities=capabilities))
        if scope is not None:
            self.assertIs(type(scope.allowed_capabilities), tuple)
            capabilities.append("api-baseline")
            self.assertFalse(scope.allows_capability("api-baseline"))
        self.assertEqual(self.persisted(), [])

    @_SOURCE_CONTRACT
    def test_source_red_issued_asset_grant_cannot_be_widened_by_list(self):
        assets = ["in.invalid", "excluded.invalid"]
        scope = self.maybe_create(lambda: self.scope(assets=assets))
        if scope is None:
            self.assertEqual(self.persisted(), [])
            return
        grant = self.issue(scope)
        before = self.persisted()
        assets.append("outside.invalid")
        self.assertFalse(grant.scope.allows_asset("outside.invalid"))
        self.assertEqual(self.persisted(), before)

    @_SOURCE_CONTRACT
    def test_source_red_issued_exclusion_cannot_be_erased_by_list(self):
        excluded = ["excluded.invalid"]
        scope = self.maybe_create(lambda: self.scope(excluded=excluded))
        if scope is None:
            self.assertEqual(self.persisted(), [])
            return
        grant = self.issue(scope)
        before = self.persisted()
        excluded.clear()
        self.assertFalse(grant.scope.allows_asset("excluded.invalid"))
        self.assertEqual(self.persisted(), before)

    @_SOURCE_CONTRACT
    def test_source_red_issued_capability_cannot_be_widened_by_list(self):
        capabilities = ["web-baseline"]
        scope = self.maybe_create(lambda: self.scope(capabilities=capabilities))
        if scope is None:
            self.assertEqual(self.persisted(), [])
            return
        grant = self.issue(scope)
        before = self.persisted()
        capabilities.append("api-baseline")
        self.assertFalse(grant.scope.allows_capability("api-baseline"))
        self.assertEqual(self.persisted(), before)


if __name__ == "__main__":
    unittest.main()
