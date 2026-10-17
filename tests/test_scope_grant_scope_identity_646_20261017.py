"""#646: original durable grant issuance must accept only exact ScopeDefinition.

Acceptance-only, deliberately owner-isolated.  All data is synthetic and stored
in a temporary SQLite database.  Never invokes scanners, handlers or networks.

Default run keeps original defects as expected failures.  Once the domain owner
repairs issuance, set LIGHTUP_SCOPE646_REQUIRE_SOURCE_FIX=1 to require all
contract tests to pass ordinarily (no expectedFailures).
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.engagements import RiskLevel, ScopeDefinition


# Explicit opt-in strict gate; anything except literal "1" remains source-RED.
_SOURCE_CONTRACT = (
    (lambda function: function)
    if os.environ.get("LIGHTUP_SCOPE646_REQUIRE_SOURCE_FIX") == "1"
    else unittest.expectedFailure
)


class FlippingScope(ScopeDefinition):
    """Synthetic subclass: safe at validation, destructive at persistence."""

    def __getattribute__(self, name):
        if name == "max_risk":
            reads = object.__getattribute__(self, "_scope646_risk_reads")
            object.__setattr__(self, "_scope646_risk_reads", reads + 1)
            return (
                RiskLevel.STANDARD
                if reads < 2
                else RiskLevel.DESTRUCTIVE_LAB_ONLY
            )
        return object.__getattribute__(self, name)


class CanonicalGrantScopeAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope646_")
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "offline.db")
        self.operator = AccessContext("fictional-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional #646 Client")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "Fictional audit only"
        )
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(minutes=5)
        self.end = now + timedelta(hours=2)

    @staticmethod
    def scope():
        return ScopeDefinition(
            assets=("offline.example.invalid",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
            excluded_assets=(),
        )

    def issue(self, scope):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id,
            "Synthetic operator", "SYNTHETIC-NOT-CONSENT",
            scope, self.start, self.end,
        )

    def durable_count(self):
        with sqlite3.connect(self.store.path) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM authorization_grants "
                "WHERE engagement_id=?", (self.engagement.engagement_id,)
            ).fetchone()[0]

    def test_exact_canonical_scope_unchanged_and_persisted(self):
        canonical = self.scope()
        grant = self.issue(canonical)
        self.assertIs(type(grant.scope), ScopeDefinition)
        self.assertEqual(grant.scope.max_risk, RiskLevel.STANDARD)
        self.assertEqual(self.durable_count(), 1)
        with sqlite3.connect(self.store.path) as connection:
            row = connection.execute(
                "SELECT max_risk, assets_json, allowed_capabilities_json "
                "FROM authorization_grants WHERE grant_id=?", (grant.grant_id,)
            ).fetchone()
        self.assertEqual(row[0], int(RiskLevel.STANDARD))
        self.assertEqual(row[1], '["offline.example.invalid"]')
        self.assertEqual(row[2], '["web-baseline"]')

    def test_exact_canonical_scope_consecutive_issuance_remains_supported(self):
        self.issue(self.scope())
        self.issue(self.scope())
        self.assertEqual(self.durable_count(), 2)

    def test_client_context_still_cannot_issue_grants(self):
        ctx = AccessContext(
            "fictional-client", Role.CLIENT_ADMIN,
            self.engagement.client_id,
        )
        with self.assertRaises(RoleError):
            self.store.record_authorization_grant(
                ctx, self.engagement.engagement_id, "x", "y", self.scope(),
                self.start, self.end,
            )
        self.assertEqual(self.durable_count(), 0)

    @_SOURCE_CONTRACT
    def test_source_red_structural_duck_scope_fails_atomically(self):
        duck = SimpleNamespace(
            assets=("offline.example.invalid",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
            excluded_assets=(),
        )
        with self.assertRaises((ValueError, TypeError)):
            self.issue(duck)
        self.assertEqual(self.durable_count(), 0)

    @_SOURCE_CONTRACT
    def test_source_red_scope_subclass_fails_atomically(self):
        class HarmlessSubclass(ScopeDefinition):
            pass
        copy = self.scope()
        noncanonical = HarmlessSubclass(
            assets=copy.assets, max_risk=copy.max_risk,
            allowed_capabilities=copy.allowed_capabilities,
            excluded_assets=copy.excluded_assets,
        )
        with self.assertRaises((ValueError, TypeError)):
            self.issue(noncanonical)
        self.assertEqual(self.durable_count(), 0)

    @_SOURCE_CONTRACT
    def test_source_red_flipping_subclass_cannot_persist_destructive_risk(self):
        canonical = self.scope()
        unstable = FlippingScope(
            assets=canonical.assets,
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=canonical.allowed_capabilities,
            excluded_assets=canonical.excluded_assets,
        )
        object.__setattr__(unstable, "_scope646_risk_reads", 0)
        try:
            self.issue(unstable)
        except (ValueError, TypeError):
            # The desired source-owner behavior: deny before persistence.
            pass
        else:
            # On the unpatched source this reaches SQLite with risk=5.
            with sqlite3.connect(self.store.path) as connection:
                stored = connection.execute(
                    "SELECT max_risk FROM authorization_grants "
                    "WHERE engagement_id=?", (self.engagement.engagement_id,)
                ).fetchone()
            if stored is not None:
                self.assertNotEqual(
                    stored[0], int(RiskLevel.DESTRUCTIVE_LAB_ONLY),
                    "unpatched source persisted destructive risk after safe validation",
                )
            self.fail("noncanonical scope subclass passed issuance")
        self.assertEqual(self.durable_count(), 0)

    @_SOURCE_CONTRACT
    def test_source_red_none_scope_is_invalid_not_attribute_error(self):
        with self.assertRaises((ValueError, TypeError)):
            self.issue(None)
        self.assertEqual(self.durable_count(), 0)


if __name__ == "__main__":
    unittest.main()
