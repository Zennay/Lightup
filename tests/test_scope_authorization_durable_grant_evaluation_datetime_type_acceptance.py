from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


class _AlwaysWithinWindow(datetime):
    """Adversarial evaluation instant that claims both window comparisons pass."""

    def __ge__(self, other: object) -> bool:
        return True

    def __le__(self, other: object) -> bool:
        return True


def _grant(*, valid_from: datetime, valid_until: datetime) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-datetime-type",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-DATETIME-TYPE",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=valid_from,
        valid_until=valid_until,
    )


class DurableGrantEvaluationDatetimeTypeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)

    def test_exact_builtin_evaluation_datetime_keeps_inclusive_boundaries(self) -> None:
        grant = _grant(
            valid_from=self.t0,
            valid_until=self.t0 + timedelta(hours=1),
        )

        self.assertTrue(grant.is_current(self.t0))
        self.assertTrue(grant.is_current(self.t0 + timedelta(hours=1)))

    def test_datetime_subclass_cannot_spoof_future_grant_as_current(self) -> None:
        grant = _grant(
            valid_from=self.t0 + timedelta(hours=1),
            valid_until=self.t0 + timedelta(hours=2),
        )
        supplied = _AlwaysWithinWindow(
            2026,
            10,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        with self.assertRaisesRegex(ValueError, "authorization time"):
            grant.is_current(supplied)

    def test_datetime_subclass_cannot_spoof_expired_grant_as_current(self) -> None:
        grant = _grant(
            valid_from=self.t0 - timedelta(hours=2),
            valid_until=self.t0 - timedelta(hours=1),
        )
        supplied = _AlwaysWithinWindow(
            2026,
            10,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        )

        with self.assertRaisesRegex(ValueError, "authorization time"):
            grant.is_current(supplied)


if __name__ == "__main__":
    unittest.main()
