from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


def _grant(*, valid_from: datetime, valid_until: datetime) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-window",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-WINDOW",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=valid_from,
        valid_until=valid_until,
    )


class DurableGrantTimeWindowAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.start = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
        self.end = self.start + timedelta(hours=2)
        self.grant = _grant(valid_from=self.start, valid_until=self.end)

    def test_window_boundaries_are_inclusive(self) -> None:
        self.assertTrue(self.grant.is_current(self.start))
        self.assertTrue(self.grant.is_current(self.end))

    def test_before_start_and_after_expiry_are_not_current(self) -> None:
        self.assertFalse(self.grant.is_current(self.start - timedelta(microseconds=1)))
        self.assertFalse(self.grant.is_current(self.end + timedelta(microseconds=1)))

    def test_equivalent_timezone_aware_instant_compares_consistently(self) -> None:
        plus_two = timezone(timedelta(hours=2))
        equivalent = datetime(2026, 10, 7, 14, 0, tzinfo=plus_two)

        self.assertEqual(equivalent, self.start)
        self.assertTrue(self.grant.is_current(equivalent))

    def test_naive_evaluation_clock_is_rejected(self) -> None:
        naive = self.start.replace(tzinfo=None)

        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self.grant.is_current(naive)

    def test_inverted_direct_window_can_never_be_current(self) -> None:
        inverted = _grant(valid_from=self.end, valid_until=self.start)

        self.assertFalse(inverted.is_current(self.start))
        self.assertFalse(inverted.is_current(self.start + timedelta(hours=1)))
        self.assertFalse(inverted.is_current(self.end))


if __name__ == "__main__":
    unittest.main()
