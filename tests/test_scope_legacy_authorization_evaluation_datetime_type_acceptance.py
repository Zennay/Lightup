import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization


class ComparisonSpoofingDateTime(datetime):
    """Adversarial datetime subclass that suppresses validity-window comparisons."""

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return False


class LegacyAuthorizationEvaluationDateTimeTypeAcceptanceTests(unittest.TestCase):
    def test_polymorphic_evaluation_time_cannot_bypass_future_valid_from(self):
        auth = Authorization(
            owner="owner",
            reference="AUTH-FUTURE",
            valid_from=datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc),
        )
        spoofed_now = ComparisonSpoofingDateTime(
            2026, 10, 7, 12, 0, tzinfo=timezone.utc
        )

        with self.assertRaises(ValueError):
            auth.is_current(spoofed_now)

    def test_polymorphic_evaluation_time_cannot_bypass_expired_valid_until(self):
        auth = Authorization(
            owner="owner",
            reference="AUTH-EXPIRED",
            valid_until=datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc),
        )
        spoofed_now = ComparisonSpoofingDateTime(
            2026, 10, 7, 12, 0, tzinfo=timezone.utc
        )

        with self.assertRaises(ValueError):
            auth.is_current(spoofed_now)

    def test_exact_builtin_evaluation_time_keeps_inclusive_boundaries(self):
        exact_now = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
        auth = Authorization(
            owner="owner",
            reference="AUTH-BOUNDARY",
            valid_from=exact_now,
            valid_until=exact_now,
        )

        self.assertTrue(auth.is_current(exact_now))


if __name__ == "__main__":
    unittest.main()
