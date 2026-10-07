import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization


class AuthorizationEvaluationTimeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc)
        self.authorization = Authorization(
            owner="example-owner",
            reference="AUTH-403",
            valid_from=self.now - timedelta(minutes=5),
            valid_until=self.now + timedelta(minutes=5),
        )

    def assert_invalid_clock_fails_closed(self, value):
        try:
            self.authorization.is_current(value)  # type: ignore[arg-type]
        except Exception as exc:
            self.assertIs(
                type(exc),
                ValueError,
                f"{type(value).__name__} must fail closed as ValueError, got {type(exc).__name__}",
            )
        else:
            self.fail(f"{type(value).__name__} evaluation time was silently accepted")

    def test_canonical_aware_datetime_remains_current(self):
        self.assertTrue(self.authorization.is_current(self.now))

    def test_omitted_clock_remains_supported(self):
        current = Authorization(
            owner="example-owner",
            reference="AUTH-403-OPEN",
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.assertTrue(current.is_current())

    def test_false_clock_fails_closed(self):
        self.assert_invalid_clock_fails_closed(False)

    def test_zero_clock_fails_closed(self):
        self.assert_invalid_clock_fails_closed(0)

    def test_empty_text_clock_fails_closed(self):
        self.assert_invalid_clock_fails_closed("")

    def test_truthy_boolean_clock_fails_closed(self):
        self.assert_invalid_clock_fails_closed(True)

    def test_truthy_text_clock_fails_closed(self):
        self.assert_invalid_clock_fails_closed("2026-10-07T10:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
