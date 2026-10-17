"""#776: cross-family ScopeDefinition type/collection/risk composition.

Not a source-owner implementation. All identities are synthetic .invalid labels.
Original source REDs remain expectedFailure unless explicitly opted into strict
LIGHTUP_SCOPE776_REQUIRE_SOURCE_FIX=1 after the owner implements a fix.
Does not import or modify work owned by #648, #773 or #775 workers.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


_SOURCE_CONTRACT = (
    (lambda test: test)
    if os.environ.get("LIGHTUP_SCOPE776_REQUIRE_SOURCE_FIX") == "1"
    else unittest.expectedFailure
)


class ForeignRisk(IntEnum):
    FICTITIOUS = 99


class UntrustedTuple(tuple):
    visits = 0

    def __iter__(self):
        type(self).visits += 1
        raise AssertionError("noncanonical tuple iterator executed")


class UntrustedText(str):
    reads = 0

    def strip(self, *args, **kwargs):
        type(self).reads += 1
        raise AssertionError("noncanonical string normalization executed")


class ComposedScopeIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope776_")
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "synthetic.sqlite3")
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional 776")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "No real authority"
        )
        self.engagement_id = engagement.engagement_id
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(minutes=1)
        self.end = now + timedelta(hours=1)

    @staticmethod
    def scope(*, assets=("valid.invalid", "excluded.invalid"),
              excluded_assets=("excluded.invalid",),
              allowed_capabilities=("web-baseline",),
              max_risk=RiskLevel.STANDARD):
        return ScopeDefinition(
            assets=assets,
            excluded_assets=excluded_assets,
            allowed_capabilities=allowed_capabilities,
            max_risk=max_risk,
        )

    def issue(self, scope):
        return self.store.record_authorization_grant(
            self.operator, self.engagement_id,
            "Fictional CISO", "SYNTHETIC-NOT-CONSENT",
            scope, self.start, self.end,
        )

    def rows(self):
        with closing(sqlite3.connect(self.store.path)) as connection:
            return connection.execute(
                "SELECT grant_id, assets_json, excluded_assets_json, "
                "allowed_capabilities_json, max_risk FROM authorization_grants "
                "WHERE engagement_id=? ORDER BY grant_id", (self.engagement_id,)
            ).fetchall()

    def test_exact_all_three_fields_preserve_behavior(self):
        scope = self.scope()
        self.assertIs(type(scope.max_risk), RiskLevel)
        for values in (scope.assets, scope.excluded_assets, scope.allowed_capabilities):
            self.assertIs(type(values), tuple)
            for value in values:
                self.assertIs(type(value), str)
        self.assertTrue(scope.allows_asset("valid.invalid"))
        self.assertFalse(scope.allows_asset("excluded.invalid"))
        self.assertFalse(scope.allows_asset("outside.invalid"))
        self.assertTrue(scope.allows_capability("web-baseline"))
        self.assertFalse(scope.allows_capability("ot-lab"))
        self.assertEqual(self.rows(), [])

    def test_exact_composed_grant_sqlite_snapshot(self):
        scope = self.scope()
        grant = self.issue(scope)
        self.assertEqual(grant.scope, scope)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0][4], int(RiskLevel.STANDARD))
        self.assertFalse(grant.scope.allows_asset("excluded.invalid"))
        self.assertFalse(grant.scope.allows_capability("api-baseline"))

    def test_invalid_empty_assets_remain_denied_without_insert(self):
        with self.assertRaises((ValueError, TypeError)):
            self.issue(self.scope(assets=()))
        self.assertEqual(self.rows(), [])

    @_SOURCE_CONTRACT
    def test_source_red_all_three_invalid_dimensions_rejected_at_construction(self):
        # A weak repair of just risk, tuples, or entries must not be sufficient.
        for risk, assets, caps in (
            (99, ["valid.invalid"], ("web-baseline",)),
            (RiskLevel.STANDARD, ("valid.invalid",), (UntrustedText("web-baseline"),)),
            (ForeignRisk.FICTITIOUS, ("valid.invalid",), ["web-baseline"]),
        ):
            with self.subTest(risk=type(risk).__name__, assets=type(assets).__name__):
                with self.assertRaises((ValueError, TypeError)):
                    self.scope(max_risk=risk, assets=assets,
                               allowed_capabilities=caps)
        self.assertEqual(self.rows(), [])

    @_SOURCE_CONTRACT
    def test_source_red_foreign_risk_and_tuple_must_not_execute_protocols(self):
        UntrustedTuple.visits = 0
        hostile = UntrustedTuple(("valid.invalid",))
        with self.assertRaises((ValueError, TypeError)):
            self.scope(max_risk=ForeignRisk.FICTITIOUS, assets=hostile)
        self.assertEqual(UntrustedTuple.visits, 0)
        self.assertEqual(self.rows(), [])

    @_SOURCE_CONTRACT
    def test_source_red_exact_tuple_nonexact_text_must_not_run_strip(self):
        UntrustedText.reads = 0
        hostile = UntrustedText("valid.invalid")
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=(hostile,))
        self.assertEqual(UntrustedText.reads, 0)
        self.assertEqual(self.rows(), [])

    @_SOURCE_CONTRACT
    def test_source_red_bool_risk_is_not_an_enum_even_if_equal(self):
        for risk in (True, False, 0, 3, 5, 99, ForeignRisk.FICTITIOUS):
            with self.subTest(risk=repr(risk)):
                with self.assertRaises((ValueError, TypeError)):
                    self.scope(max_risk=risk)
        self.assertEqual(self.rows(), [])

    @_SOURCE_CONTRACT
    def test_source_red_original_grant_cannot_be_mutated_via_composed_aliases(self):
        grant = self.issue(self.scope())
        before = self.rows()
        owned = ["valid.invalid", "excluded.invalid"]
        excluded = ["excluded.invalid"]
        caps = ["web-baseline"]
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=owned, excluded_assets=excluded,
                       allowed_capabilities=caps, max_risk=99)
        owned.append("outside.invalid")
        excluded.clear()
        caps.append("api-baseline")
        self.assertEqual(self.rows(), before)
        self.assertFalse(grant.scope.allows_asset("outside.invalid"))
        self.assertFalse(grant.scope.allows_asset("excluded.invalid"))
        self.assertFalse(grant.scope.allows_capability("api-baseline"))


if __name__ == "__main__":
    unittest.main()
