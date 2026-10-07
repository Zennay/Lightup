from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class _BenignCapabilityString(str):
    pass


class _RegistryIdentitySpoof(str):
    """Keep one persisted value while comparing/hashing as another registry key."""

    def __new__(cls, stored_value: str, spoofed_registry_value: str):
        obj = super().__new__(cls, stored_value)
        obj._spoofed_registry_value = spoofed_registry_value
        return obj

    def __hash__(self) -> int:
        return hash(self._spoofed_registry_value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return (
                other == self._spoofed_registry_value
                or str.__eq__(self, other)
            )
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class GrantCapabilityInputTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-capability-input", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Grant Capability Input Type Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Canonical grant capability identities",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(hours=1)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant_rows(self) -> tuple[str, ...]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT allowed_capabilities_json FROM authorization_grants "
                "WHERE engagement_id=? ORDER BY created_at",
                (self.engagement.engagement_id,),
            ).fetchall()
        return tuple(row["allowed_capabilities_json"] for row in rows)

    def _record(self, capability_id: str):
        scope = ScopeDefinition(
            assets=("app.capability-input.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(capability_id,),
        )
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Capability",
            "AUTH-CAPABILITY-001",
            scope,
            self.valid_from,
            self.valid_until,
        )

    def _assert_noncanonical_capability_rejected_without_write(
        self, capability_id: str
    ) -> None:
        before = self._grant_rows()
        with self.assertRaises(
            ValueError,
            msg="non-canonical capability identities must fail before persistence",
        ):
            self._record(capability_id)
        self.assertEqual(
            self._grant_rows(),
            before,
            "rejected capability identities must not create durable grant rows",
        )

    def test_builtin_planning_capability_remains_accepted_unchanged(self) -> None:
        grant = self._record("web-baseline")

        self.assertEqual(grant.scope.allowed_capabilities, ("web-baseline",))
        self.assertTrue(grant.scope.allows_capability("web-baseline"))
        rows = self._grant_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]), ["web-baseline"])

    def test_benign_string_subclass_is_rejected_before_persistence(self) -> None:
        self._assert_noncanonical_capability_rejected_without_write(
            _BenignCapabilityString("web-baseline")
        )

    def test_lab_only_identity_cannot_spoof_planning_registry_key(self) -> None:
        forged = _RegistryIdentitySpoof("ot-lab", "web-baseline")
        before = self._grant_rows()

        try:
            grant = self._record(forged)
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertEqual(
                json.loads(rows[-1]),
                ["ot-lab"],
                "fixture must prove persistence observes the underlying LAB_ONLY identity",
            )
            self.assertTrue(
                grant.scope.allows_capability("ot-lab"),
                "accepted polymorphic scope retains LAB_ONLY authority in memory",
            )
            self.fail(
                "LAB_ONLY capability identity spoofed a planning registry key at issuance"
            )

        self.assertEqual(
            self._grant_rows(),
            before,
            "LAB_ONLY spoof rejection must be write-atomic",
        )

    def test_unknown_identity_cannot_spoof_planning_registry_key(self) -> None:
        forged = _RegistryIdentitySpoof(
            "future-unknown-capability",
            "web-baseline",
        )
        before = self._grant_rows()

        try:
            self._record(forged)
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertEqual(
                json.loads(rows[-1]),
                ["future-unknown-capability"],
                "fixture must prove persistence observes the unknown underlying identity",
            )
            self.fail(
                "unknown capability identity spoofed a planning registry key at issuance"
            )

        self.assertEqual(
            self._grant_rows(),
            before,
            "unknown capability spoof rejection must be write-atomic",
        )


if __name__ == "__main__":
    unittest.main()
