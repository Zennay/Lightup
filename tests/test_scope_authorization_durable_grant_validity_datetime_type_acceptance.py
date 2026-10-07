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


def _grant(*, valid_from: object, valid_until: object) -> AuthorizationGrant:
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
        valid_from=valid_from,  # type: ignore[arg-type]
        valid_until=valid_until,  # type: ignore[arg-type]
    )


class DurableGrantValidityDatetimeTypeAcceptanceTests(unittest.TestCase):
    def _assert_controlled_rejection(self, grant: AuthorizationGrant) -> None:
        try:
            grant.is_current(NOW)
        except Exception as exc:  # acceptance distinguishes validation from incidental comparison errors
            self.assertIs(type(exc), ValueError)
        else:
            self.fail("malformed stored authorization datetime must fail closed")

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
        self._assert_controlled_rejection(
            _grant(valid_from=future, valid_until=NOW + timedelta(hours=2))
        )

    def test_datetime_subclass_cannot_spoof_expired_stored_end(self) -> None:
        expired = _ExpiredEnd(2026, 10, 7, 11, 0, tzinfo=timezone.utc)
        self._assert_controlled_rejection(
            _grant(valid_from=NOW - timedelta(hours=2), valid_until=expired)
        )

    def test_naive_stored_start_is_rejected_before_comparison(self) -> None:
        self._assert_controlled_rejection(
            _grant(
                valid_from=(NOW - timedelta(hours=1)).replace(tzinfo=None),
                valid_until=NOW + timedelta(hours=1),
            )
        )

    def test_naive_stored_end_is_rejected_before_comparison(self) -> None:
        self._assert_controlled_rejection(
            _grant(
                valid_from=NOW - timedelta(hours=1),
                valid_until=(NOW + timedelta(hours=1)).replace(tzinfo=None),
            )
        )

    def test_non_datetime_stored_start_is_rejected_before_comparison(self) -> None:
        self._assert_controlled_rejection(
            _grant(valid_from=0, valid_until=NOW + timedelta(hours=1))
        )

    def test_non_datetime_stored_end_is_rejected_before_comparison(self) -> None:
        self._assert_controlled_rejection(
            _grant(valid_from=NOW - timedelta(hours=1), valid_until="later")
        )


if __name__ == "__main__":
    unittest.main()
