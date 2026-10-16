"""#738: reject stored datetime subclass before invoking rich comparison.

Deterministic in-memory source-owner acceptance. No issuance, SQLite,
network, targets, scanner, runtime handler or approval authority.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
CALLS: list[str] = []


class LoggedStart(datetime):
    def __le__(self, other: object) -> bool:
        CALLS.append("foreign-start-le")
        return True


class LoggedEnd(datetime):
    def __ge__(self, other: object) -> bool:
        CALLS.append("foreign-end-ge")
        return True


class ThrowingStart(datetime):
    def __le__(self, other: object) -> bool:
        CALLS.append("throwing-start-le")
        raise RuntimeError("foreign datetime comparator executed")


def boundary(cls: type[datetime], dt: datetime) -> datetime:
    return cls(dt.year, dt.month, dt.day, dt.hour, dt.minute,
               dt.second, tzinfo=timezone.utc)


def grant(start: datetime, end: datetime) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="fictional-precomparison-738",
        client_id="synthetic-client",
        engagement_id="synthetic-engagement",
        approved_by="fictional-operator",
        reference="NOT-CONSENT-738",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.ANALYSIS_ONLY,
            allowed_capabilities=(),
        ),
        valid_from=start,
        valid_until=end,
    )


class GrantStoredPrecomparisonSourceRED738(unittest.TestCase):
    def setUp(self) -> None:
        CALLS.clear()

    def tearDown(self) -> None:
        CALLS.clear()

    def test_canonical_current_works_without_untrusted_hooks(self) -> None:
        g = grant(NOW - timedelta(minutes=1), NOW + timedelta(minutes=1))
        self.assertTrue(g.is_current(NOW))
        self.assertEqual(CALLS, [])

    def test_canonical_future_start_denied_without_untrusted_hooks(self) -> None:
        g = grant(NOW + timedelta(days=1), NOW + timedelta(days=2))
        self.assertFalse(g.is_current(NOW))
        self.assertEqual(CALLS, [])

    @unittest.expectedFailure
    def test_logged_start_rejected_before_comparison(self) -> None:
        forged = boundary(LoggedStart, NOW + timedelta(days=1))
        g = grant(forged, NOW + timedelta(days=2))
        with self.assertRaises(ValueError):
            g.is_current(NOW)
        self.assertEqual(CALLS, [])
        self.assertIs(g.valid_from, forged)

    @unittest.expectedFailure
    def test_logged_end_rejected_before_comparison(self) -> None:
        forged = boundary(LoggedEnd, NOW - timedelta(days=1))
        g = grant(NOW - timedelta(days=2), forged)
        with self.assertRaises(ValueError):
            g.is_current(NOW)
        self.assertEqual(CALLS, [])
        self.assertIs(g.valid_until, forged)

    @unittest.expectedFailure
    def test_throwing_start_rejected_before_comparator_dispatch(self) -> None:
        forged = boundary(ThrowingStart, NOW + timedelta(days=1))
        g = grant(forged, NOW + timedelta(days=2))
        with self.assertRaises(ValueError):
            g.is_current(NOW)
        self.assertEqual(CALLS, [])
        self.assertIs(g.valid_from, forged)


if __name__ == "__main__":
    unittest.main()
