from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


class _FutureStart(datetime):
    def __le__(self, other: object) -> bool:
        return True


class _ExpiredEnd(datetime):
    def __ge__(self, other: object) -> bool:
        return True


def _grant(*, valid_from: datetime, valid_until: datetime) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-validity-type",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-VALIDITY-TYPE",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=valid_from,
        valid_until=valid_until,
    )


class DurableGrantValidityDatetimeTypeAcceptanceTests(unittest.TestCase):
    def test_exact_builtin_future_start_remains_denied(self) -> None:
        grant = _grant(
            valid_from=NOW + timedelta(hours=1),
            valid_until=NOW + timedelta(hours=2),
        )

        self.assertFalse(grant.is_current(NOW))

    def test_exact_builtin_expired_end_remains_denied(self) -> None:
        grant = _grant(
            valid_from=NOW - timedelta(hours=2),
            valid_until=NOW - timedelta(hours=1),
        )

        self.assertFalse(grant.is_current(NOW))

    def test_datetime_subclass_cannot_spoof_future_stored_start(self) -> None:
        future = _FutureStart(2026, 10, 7, 13, 0, tzinfo=timezone.utc)
        grant = _grant(
            valid_from=future,
            valid_until=NOW + timedelta(hours=2),
        )

        with self.assertRaises(ValueError):
            grant.is_current(NOW)

    def test_datetime_subclass_cannot_spoof_expired_stored_end(self) -> None:
        expired = _ExpiredEnd(2026, 10, 7, 11, 0, tzinfo=timezone.utc)
        grant = _grant(
            valid_from=NOW - timedelta(hours=2),
            valid_until=expired,
        )

        with self.assertRaises(ValueError):
            grant.is_current(NOW)


if __name__ == "__main__":
    unittest.main()
