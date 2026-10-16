"""Issue #738: acceptance tests for *stored* grant datetime subclasses.

Pinned to source-owner PR #100, exact commit ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f.
Tests only; no grant issuance, durable I/O, execution, or target interaction.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


class FalseFutureStart(datetime):
    """Untrusted future start that lies when compared as left operand."""
    def __le__(self, other: object) -> bool:
        return True


class FalseValidEnd(datetime):
    """Untrusted expired end that lies as reflected right-hand operand."""
    def __ge__(self, other: object) -> bool:
        return True


def grant(start: datetime, end: datetime) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-fictional-738",
        client_id="fictional-client",
        engagement_id="fictional-engagement",
        approved_by="fictional-operator",
        reference="SYNTHETIC-NO-CONSENT-738",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.ANALYSIS_ONLY,
            allowed_capabilities=(),
        ),
        valid_from=start,
        valid_until=end,
    )


def subclass_start() -> datetime:
    later = NOW + DAY
    return FalseFutureStart(
        later.year, later.month, later.day,
        later.hour, later.minute, later.second,
        tzinfo=timezone.utc,
    )


def subclass_end() -> datetime:
    earlier = NOW - DAY
    return FalseValidEnd(
        earlier.year, earlier.month, earlier.day,
        earlier.hour, earlier.minute, earlier.second,
        tzinfo=timezone.utc,
    )


class GrantValidityControl738(unittest.TestCase):
    def test_canonical_current_window(self) -> None:
        self.assertTrue(grant(NOW - DAY, NOW + DAY).is_current(NOW))

    def test_canonical_future_start_is_denied(self) -> None:
        self.assertFalse(grant(NOW + DAY, NOW + 2 * DAY).is_current(NOW))

    def test_canonical_expired_end_is_denied(self) -> None:
        self.assertFalse(grant(NOW - 2 * DAY, NOW - DAY).is_current(NOW))

    def test_canonical_exact_start_boundary_is_inclusive(self) -> None:
        self.assertTrue(grant(NOW, NOW + DAY).is_current(NOW))

    def test_canonical_exact_end_boundary_is_inclusive(self) -> None:
        self.assertTrue(grant(NOW - DAY, NOW).is_current(NOW))

    def test_canonical_revocation_denies(self) -> None:
        g = grant(NOW - DAY, NOW + DAY)
        revoked = AuthorizationGrant(
            **{**g.__dict__, "revoked_at": NOW - timedelta(seconds=1)}
        )
        self.assertFalse(revoked.is_current(NOW))


class StoredDatetimeSubclassSourceOwnerRED738(unittest.TestCase):
    """Known owner REDs; convert to ordinary PASS after explicit type fence."""

    @unittest.expectedFailure
    def test_fake_future_lower_bound_must_be_rejected(self) -> None:
        bad = grant(subclass_start(), NOW + 2 * DAY)
        with self.assertRaises(ValueError):
            bad.is_current(NOW)

    @unittest.expectedFailure
    def test_fake_expired_upper_bound_must_be_rejected(self) -> None:
        bad = grant(NOW - 2 * DAY, subclass_end())
        with self.assertRaises(ValueError):
            bad.is_current(NOW)

    @unittest.expectedFailure
    def test_validity_subclass_must_be_rejected_even_if_it_returns_false(self) -> None:
        bad = grant(subclass_start(), NOW - DAY)
        with self.assertRaises(ValueError):
            bad.is_current(NOW)

    @unittest.expectedFailure
    def test_subclass_boundaries_must_not_be_mutated_or_repaired(self) -> None:
        start = subclass_start()
        end = subclass_end()
        bad = grant(start, end)
        with self.assertRaises(ValueError):
            bad.is_current(NOW)
        self.assertIs(bad.valid_from, start)
        self.assertIs(bad.valid_until, end)


if __name__ == "__main__":
    unittest.main()
