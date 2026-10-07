from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class _EquivalentDuckScope:
    assets = ("app.scope-object.example",)
    excluded_assets = ()
    allowed_capabilities = ("web-baseline",)
    max_risk = RiskLevel.STANDARD


class _OscillatingRiskScope:
    assets = ("app.scope-object.example",)
    excluded_assets = ()
    allowed_capabilities = ("web-baseline",)

    def __init__(self) -> None:
        self._risk_reads = 0

    @property
    def max_risk(self) -> RiskLevel:
        self._risk_reads += 1
        if self._risk_reads <= 2:
            return RiskLevel.STANDARD
        return RiskLevel.DESTRUCTIVE_LAB_ONLY


class _ScopeDefinitionSubclass(ScopeDefinition):
    pass


class GrantScopeObjectTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-scope-object", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Grant Scope Object Type Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Grant scope object boundary",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(hours=1)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant_count(self) -> int:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT COUNT(*) AS count FROM authorization_grants "
                "WHERE engagement_id=?",
                (self.engagement.engagement_id,),
            ).fetchone()
        assert row is not None
        return int(row["count"])

    def _persisted_risks(self) -> tuple[int, ...]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT max_risk FROM authorization_grants "
                "WHERE engagement_id=? ORDER BY created_at",
                (self.engagement.engagement_id,),
            ).fetchall()
        return tuple(int(row["max_risk"]) for row in rows)

    def _record(self, scope: object):
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Scope Object",
            "AUTH-SCOPE-OBJECT-001",
            scope,  # type: ignore[arg-type]
            self.valid_from,
            self.valid_until,
        )

    def _assert_noncanonical_scope_rejected_without_write(self, scope: object) -> None:
        before = self._grant_count()
        with self.assertRaises(
            ValueError,
            msg="non-canonical scope objects must fail before durable grant persistence",
        ):
            self._record(scope)
        self.assertEqual(
            self._grant_count(),
            before,
            "rejected scope input must not create an authorization grant row",
        )

    def test_exact_scope_definition_remains_accepted(self) -> None:
        scope = ScopeDefinition(
            assets=("app.scope-object.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        grant = self._record(scope)

        self.assertIs(type(grant.scope), ScopeDefinition)
        self.assertEqual(self._grant_count(), 1)
        self.assertEqual(self._persisted_risks(), (int(RiskLevel.STANDARD),))

    def test_structurally_equivalent_duck_scope_is_rejected(self) -> None:
        self._assert_noncanonical_scope_rejected_without_write(_EquivalentDuckScope())

    def test_scope_definition_subclass_is_rejected(self) -> None:
        scope = _ScopeDefinitionSubclass(
            assets=("app.scope-object.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self._assert_noncanonical_scope_rejected_without_write(scope)

    def test_oscillating_scope_cannot_switch_risk_after_validation(self) -> None:
        before = self._grant_count()
        scope = _OscillatingRiskScope()

        try:
            self._record(scope)
        except ValueError:
            pass
        else:
            persisted = self._persisted_risks()
            self.assertNotIn(
                int(RiskLevel.DESTRUCTIVE_LAB_ONLY),
                persisted,
                "scope TOCTOU must never persist destructive client authority",
            )
            self.fail("non-canonical scope object was accepted")

        self.assertEqual(
            self._grant_count(),
            before,
            "rejected polymorphic scope input must leave durable grants unchanged",
        )


if __name__ == "__main__":
    unittest.main()
