from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class _ComparisonSpoofDatetime(datetime):
    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return False


class LegacyAuthorizationValidityDatetimeTypeAcceptanceTest(unittest.TestCase):
    NOW = datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc)

    @staticmethod
    def _policy() -> ScopePolicy:
        return ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

    def _decision(
        self,
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            valid_from=valid_from,
            valid_until=valid_until,
        )
        return self._policy().decide(
            Target("security.example.test", authorization=authorization)
        )

    def test_future_datetime_subclass_cannot_spoof_not_before_check(self):
        future = self.NOW + timedelta(days=1)
        spoofed = _ComparisonSpoofDatetime(
            future.year,
            future.month,
            future.day,
            future.hour,
            future.minute,
            future.second,
            tzinfo=timezone.utc,
        )
        decision = self._decision(valid_from=spoofed)
        if decision.allowed:
            self.fail("polymorphic valid_from bypassed the not-before boundary")

    def test_expired_datetime_subclass_cannot_spoof_expiry_check(self):
        past = self.NOW - timedelta(days=1)
        spoofed = _ComparisonSpoofDatetime(
            past.year,
            past.month,
            past.day,
            past.hour,
            past.minute,
            past.second,
            tzinfo=timezone.utc,
        )
        decision = self._decision(valid_until=spoofed)
        if decision.allowed:
            self.fail("polymorphic valid_until bypassed the expiry boundary")

    def test_canonical_future_and_expired_boundaries_remain_denied(self):
        future_decision = self._decision(valid_from=self.NOW + timedelta(days=1))
        expired_decision = self._decision(valid_until=self.NOW - timedelta(days=1))

        self.assertFalse(future_decision.allowed)
        self.assertEqual(future_decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        self.assertFalse(expired_decision.allowed)
        self.assertEqual(expired_decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)


if __name__ == "__main__":
    unittest.main()
