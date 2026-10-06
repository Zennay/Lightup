from __future__ import annotations

from datetime import datetime, timezone
import unittest

from lightup.models import Authorization


class LegacyAuthorizationEvaluationInstantTypeAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
        )

    def test_falsy_non_datetime_evaluation_instants_fail_closed(self):
        for value in (0, False, ""):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    self.authorization.is_current(value)  # type: ignore[arg-type]

    def test_timezone_aware_datetime_keeps_existing_behavior(self):
        now = datetime(2026, 10, 6, 20, 0, tzinfo=timezone.utc)
        self.assertTrue(self.authorization.is_current(now))

    def test_none_keeps_omitted_clock_behavior(self):
        self.assertTrue(self.authorization.is_current(None))


if __name__ == "__main__":
    unittest.main()
