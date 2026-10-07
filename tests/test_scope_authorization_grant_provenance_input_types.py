from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class _BenignStringSubclass(str):
    pass


class _ChangingStripString(str):
    def __new__(cls, value: str, first: str, later: str):
        obj = super().__new__(cls, value)
        obj._strip_calls = 0
        obj._first = first
        obj._later = later
        return obj

    def strip(self, chars=None):  # type: ignore[override]
        self._strip_calls += 1
        if self._strip_calls == 1:
            return self._first
        return self._later


class GrantProvenanceInputTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-provenance-input", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Grant Provenance Input Type Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Canonical grant provenance strings",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(hours=1)
        self.scope = ScopeDefinition(
            assets=("app.provenance-input.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant_rows(self) -> tuple[tuple[str, str], ...]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT approved_by,reference FROM authorization_grants "
                "WHERE engagement_id=? ORDER BY created_at",
                (self.engagement.engagement_id,),
            ).fetchall()
        return tuple((row["approved_by"], row["reference"]) for row in rows)

    def _record(self, approved_by: str, reference: str):
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            approved_by,
            reference,
            self.scope,
            self.valid_from,
            self.valid_until,
        )

    def _assert_noncanonical_provenance_rejected_without_write(
        self, approved_by: str, reference: str
    ) -> None:
        before = self._grant_rows()
        with self.assertRaises(
            ValueError,
            msg="non-canonical provenance strings must fail before persistence",
        ):
            self._record(approved_by, reference)
        self.assertEqual(self._grant_rows(), before)

    def test_builtin_strings_remain_trimmed_and_accepted(self) -> None:
        grant = self._record("  CISO Example  ", "  AUTH-REF-001  ")

        self.assertIs(type(grant.approved_by), str)
        self.assertIs(type(grant.reference), str)
        self.assertEqual(grant.approved_by, "CISO Example")
        self.assertEqual(grant.reference, "AUTH-REF-001")
        self.assertEqual(
            self._grant_rows(),
            (("CISO Example", "AUTH-REF-001"),),
        )

    def test_benign_string_subclass_is_rejected(self) -> None:
        self._assert_noncanonical_provenance_rejected_without_write(
            _BenignStringSubclass("CISO Example"),
            "AUTH-REF-001",
        )

    def test_approved_by_cannot_change_between_validation_and_persistence(self) -> None:
        approved_by = _ChangingStripString(
            "underlying-actor",
            "CISO Checked",
            "",
        )
        before = self._grant_rows()

        try:
            self._record(approved_by, "AUTH-REF-001")
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertNotEqual(
                rows[-1][0],
                "",
                "validated approval provenance must not become blank at persistence",
            )
            self.fail("polymorphic approved_by string was accepted")

        self.assertEqual(self._grant_rows(), before)

    def test_reference_cannot_change_between_validation_and_persistence(self) -> None:
        reference = _ChangingStripString(
            "underlying-reference",
            "AUTH-CHECKED-001",
            "",
        )
        before = self._grant_rows()

        try:
            self._record("CISO Example", reference)
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertNotEqual(
                rows[-1][1],
                "",
                "validated authorization reference must not become blank at persistence",
            )
            self.fail("polymorphic authorization reference was accepted")

        self.assertEqual(self._grant_rows(), before)


if __name__ == "__main__":
    unittest.main()
