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
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch
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
        with closing(sqlite3.connect(self.store.path)) as connection:
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
        with closing(sqlite3.connect(self.store.path)) as connection:
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
            with closing(sqlite3.connect(self.store.path)) as connection:
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

    @_SOURCE_CONTRACT
    def test_source_red_forged_class_metadata_does_not_mint_scope_identity(self):
        # A forged __class__ can fool an isinstance-only future repair.
        # The owner invariant is the stricter type(scope) is ScopeDefinition.
        class Spoof:
            assets = ("offline.example.invalid",)
            max_risk = RiskLevel.STANDARD
            allowed_capabilities = ("web-baseline",)
            excluded_assets = ()

            @property
            def __class__(self):
                return ScopeDefinition

        spoof = Spoof()
        self.assertIsNot(type(spoof), ScopeDefinition)
        with self.assertRaises((ValueError, TypeError)):
            self.issue(spoof)
        self.assertEqual(self.durable_count(), 0)

    @_SOURCE_CONTRACT
    def test_source_red_rejects_foreign_scope_without_accessing_fields(self):
        # No untrusted property or other code should run to validate identity.
        class ForeignFieldTrap:
            def __init__(self):
                object.__setattr__(self, "reads", 0)

            def __getattribute__(self, name):
                if name in {
                    "assets", "excluded_assets", "allowed_capabilities",
                    "max_risk",
                }:
                    reads = object.__getattribute__(self, "reads")
                    object.__setattr__(self, "reads", reads + 1)
                    raise RuntimeError("scope field trap was evaluated")
                return object.__getattribute__(self, name)

        trap = ForeignFieldTrap()
        with self.assertRaises((ValueError, TypeError)):
            self.issue(trap)
        self.assertEqual(trap.reads, 0)
        self.assertEqual(self.durable_count(), 0)


    def test_disposable_owner_guard_oracle_rejects_foreign_before_read(self):
        """Proof-of-repair only: temporary monkeypatch, never production source."""
        original = DomainStore.record_authorization_grant

        def guarded(store, ctx, engagement_id, approved_by, reference,
                    scope, valid_from, valid_until, recurring_retest_allowed=False):
            # Mirror the production authorization precedence: role check first,
            # then canonical scope type, always before foreign field reads.
            ctx.require_operator("record_authorization_grant")
            if type(scope) is not ScopeDefinition:
                raise ValueError("exact ScopeDefinition required before any read")
            return original(
                store, ctx, engagement_id, approved_by, reference,
                scope, valid_from, valid_until, recurring_retest_allowed,
            )

        class Sneaky:
            assets = ("offline.example.invalid",)
            max_risk = RiskLevel.STANDARD
            allowed_capabilities = ("web-baseline",)
            excluded_assets = ()

            @property
            def __class__(self):
                return ScopeDefinition

        class Trap:
            def __init__(self):
                object.__setattr__(self, "reads", 0)

            def __getattribute__(self, name):
                if name == "max_risk":
                    object.__setattr__(
                        self, "reads", object.__getattribute__(self, "reads") + 1
                    )
                    raise AssertionError("foreign scope field was evaluated")
                return object.__getattribute__(self, name)

        trap = Trap()
        canonical = self.scope()
        subclass = FlippingScope(
            assets=canonical.assets, max_risk=canonical.max_risk,
            allowed_capabilities=canonical.allowed_capabilities,
            excluded_assets=canonical.excluded_assets,
        )
        object.__setattr__(subclass, "_scope646_risk_reads", 0)
        duck = SimpleNamespace(
            assets=canonical.assets, max_risk=canonical.max_risk,
            allowed_capabilities=canonical.allowed_capabilities,
            excluded_assets=canonical.excluded_assets,
        )
        with patch.object(DomainStore, "record_authorization_grant", guarded):
            for candidate in (None, Sneaky(), trap, subclass, duck):
                with self.subTest(candidate=type(candidate).__name__):
                    with self.assertRaises(ValueError):
                        self.issue(candidate)
                    self.assertEqual(self.durable_count(), 0)
            self.assertEqual(trap.reads, 0)
            self.assertEqual(
                object.__getattribute__(subclass, "_scope646_risk_reads"), 0
            )

            # A malformed object is refused before opening even local SQLite:
            # no transaction, no audit persistence and no foreign property I/O.
            with patch.object(
                self.store, "_connect",
                side_effect=AssertionError("invalid scope opened SQLite"),
            ):
                with self.assertRaises(ValueError):
                    self.issue(trap)
            self.assertEqual(trap.reads, 0)

            # Additional exact-type negative controls must be rejected without
            # accidentally treating a truthy scalar or collection as a scope.
            for candidate in (False, 0, "", "scope", [], {}, object()):
                with self.subTest(primitive=type(candidate).__name__):
                    with self.assertRaises(ValueError):
                        self.issue(candidate)

            valid = self.issue(canonical)
            self.assertIs(type(valid.scope), ScopeDefinition)
            self.assertEqual(self.durable_count(), 1)

            # A denied malformed proposal cannot change an existing grant.
            with closing(sqlite3.connect(self.store.path)) as connection:
                before = connection.execute(
                    "SELECT grant_id, max_risk, assets_json, "
                    "allowed_capabilities_json FROM authorization_grants "
                    "WHERE engagement_id=? ORDER BY grant_id",
                    (self.engagement.engagement_id,),
                ).fetchall()
            for candidate in (None, Sneaky(), trap, subclass, duck):
                with self.subTest(existing_grant=type(candidate).__name__):
                    with self.assertRaises(ValueError):
                        self.issue(candidate)
                    with closing(sqlite3.connect(self.store.path)) as connection:
                        after = connection.execute(
                            "SELECT grant_id, max_risk, assets_json, "
                            "allowed_capabilities_json FROM authorization_grants "
                            "WHERE engagement_id=? ORDER BY grant_id",
                            (self.engagement.engagement_id,),
                        ).fetchall()
                    self.assertEqual(after, before)

            # Denied client role must win before any malicious scope inspection.
            unauthenticated = AccessContext(
                "fictional-client", Role.CLIENT_ADMIN, self.engagement.client_id
            )
            with self.assertRaises(RoleError):
                self.store.record_authorization_grant(
                    unauthenticated, self.engagement.engagement_id,
                    "fake", "fake", trap, self.start, self.end,
                )
            self.assertEqual(trap.reads, 0)

    def test_exact_identity_cannot_be_approximated_with_isinstance(self):
        """An instanceof-style guard can be deceived by synthetic metadata."""
        class FakeClass:
            @property
            def __class__(self):
                return ScopeDefinition

        fake = FakeClass()
        self.assertTrue(isinstance(fake, ScopeDefinition))
        self.assertIsNot(type(fake), ScopeDefinition)
        self.assertEqual(self.durable_count(), 0)


if __name__ == "__main__":
    unittest.main()
