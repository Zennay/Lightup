from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


def _plain_datetime(value: datetime) -> datetime:
    return datetime(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=value.tzinfo,
        fold=value.fold,
    )


class _FutureSerializingDatetime(datetime):
    def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
        widened = _plain_datetime(self) + timedelta(days=3650)
        return widened.isoformat(sep=sep, timespec=timespec)


class _PastSerializingDatetime(datetime):
    def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
        widened = _plain_datetime(self) - timedelta(days=3650)
        return widened.isoformat(sep=sep, timespec=timespec)


class _BenignDatetimeSubclass(datetime):
    pass


def _as_subclass(value: datetime, cls: type[datetime]) -> datetime:
    return cls(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=value.tzinfo,
        fold=value.fold,
    )


class GrantValidityDatetimeTypeAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-grant-validity-type", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Grant Validity Datetime Type Client"
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Grant validity datetime object boundary",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(hours=1)
        self.scope = ScopeDefinition(
            assets=("app.validity-type.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _grant_rows(self) -> tuple[tuple[str, str], ...]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT valid_from,valid_until FROM authorization_grants "
                "WHERE engagement_id=? ORDER BY created_at",
                (self.engagement.engagement_id,),
            ).fetchall()
        return tuple((row["valid_from"], row["valid_until"]) for row in rows)

    def _record(self, valid_from: datetime, valid_until: datetime):
        return self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "CISO Validity Type",
            "AUTH-VALIDITY-TYPE-001",
            self.scope,
            valid_from,
            valid_until,
        )

    def _assert_noncanonical_datetime_rejected_without_write(
        self, valid_from: datetime, valid_until: datetime
    ) -> None:
        before = self._grant_rows()
        with self.assertRaises(
            ValueError,
            msg="datetime subclasses must fail before durable authorization persistence",
        ):
            self._record(valid_from, valid_until)
        self.assertEqual(
            self._grant_rows(),
            before,
            "rejected validity input must not create or mutate grant rows",
        )

    def test_exact_aware_datetimes_remain_accepted(self) -> None:
        grant = self._record(self.valid_from, self.valid_until)

        self.assertIs(type(grant.valid_from), datetime)
        self.assertIs(type(grant.valid_until), datetime)
        self.assertEqual(
            self._grant_rows(),
            ((self.valid_from.isoformat(), self.valid_until.isoformat()),),
        )

    def test_benign_datetime_subclass_is_rejected(self) -> None:
        valid_until = _as_subclass(self.valid_until, _BenignDatetimeSubclass)
        self._assert_noncanonical_datetime_rejected_without_write(
            self.valid_from, valid_until
        )

    def test_valid_until_subclass_cannot_serialize_a_later_expiry(self) -> None:
        spoofed_until = _as_subclass(
            self.valid_until, _FutureSerializingDatetime
        )
        before = self._grant_rows()

        try:
            self._record(self.valid_from, spoofed_until)
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertEqual(
                rows[-1][1],
                _plain_datetime(spoofed_until).isoformat(),
                "grant persistence must never use polymorphic isoformat() output",
            )
            self.fail("non-canonical valid_until datetime was accepted")

        self.assertEqual(self._grant_rows(), before)

    def test_valid_from_subclass_cannot_serialize_an_earlier_start(self) -> None:
        spoofed_from = _as_subclass(self.valid_from, _PastSerializingDatetime)
        before = self._grant_rows()

        try:
            self._record(spoofed_from, self.valid_until)
        except ValueError:
            pass
        else:
            rows = self._grant_rows()
            self.assertEqual(len(rows), len(before) + 1)
            self.assertEqual(
                rows[-1][0],
                _plain_datetime(spoofed_from).isoformat(),
                "grant persistence must never use polymorphic isoformat() output",
            )
            self.fail("non-canonical valid_from datetime was accepted")

        self.assertEqual(self._grant_rows(), before)


if __name__ == "__main__":
    unittest.main()
