import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationWindowContractTests(unittest.TestCase):
    def test_exact_validity_boundaries_are_inclusive(self):
        boundary = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        authorization = Authorization(
            owner="example-owner",
            reference="AUTH-BOUNDARY",
            valid_from=boundary,
            valid_until=boundary,
        )

        self.assertTrue(authorization.is_current(boundary))

    def test_before_start_and_after_expiry_are_not_current(self):
        start = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        authorization = Authorization(
            owner="example-owner",
            reference="AUTH-WINDOW",
            valid_from=start,
            valid_until=end,
        )

        self.assertFalse(authorization.is_current(start - timedelta(microseconds=1)))
        self.assertFalse(authorization.is_current(end + timedelta(microseconds=1)))

    def test_inverted_window_can_never_be_current(self):
        point = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        authorization = Authorization(
            owner="example-owner",
            reference="AUTH-INVERTED",
            valid_from=point + timedelta(hours=1),
            valid_until=point - timedelta(hours=1),
        )

        for candidate in (
            point - timedelta(days=1),
            point,
            point + timedelta(days=1),
        ):
            self.assertFalse(authorization.is_current(candidate))

    def test_explicit_public_target_with_inverted_window_is_denied(self):
        now = datetime.now(timezone.utc)
        authorization = Authorization(
            owner="example-owner",
            reference="AUTH-INVERTED-PUBLIC",
            valid_from=now + timedelta(hours=1),
            valid_until=now - timedelta(hours=1),
        )
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        decision = policy.decide(
            Target("https://security.example.test/path", authorization=authorization)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_naive_evaluation_clock_is_rejected(self):
        authorization = Authorization(
            owner="example-owner",
            reference="AUTH-TZ",
        )

        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            authorization.is_current(datetime(2026, 10, 6, 12, 0))


if __name__ == "__main__":
    unittest.main()
