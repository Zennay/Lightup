from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from lightup.models import Authorization


class LegacyAuthorizationTimestampTypeAcceptanceTest(unittest.TestCase):
    NOW = datetime(2026, 10, 6, 20, 0, tzinfo=timezone.utc)

    def _assert_invalid_boundary_rejected(self, field: str, value: object) -> None:
        kwargs: dict[str, object] = {
            "owner": "client-owner",
            "reference": "client-auth-ref",
            "assets": ("security.example.test",),
            field: value,
        }
        authorization = Authorization(**kwargs)  # type: ignore[arg-type]
        try:
            current = authorization.is_current(self.NOW)
        except (TypeError, ValueError):
            return
        if current:
            self.fail("type-confused authorization timestamp was accepted")

    def test_falsy_invalid_valid_from_values_fail_closed(self):
        for value in (0, False, ""):
            with self.subTest(value=value):
                self._assert_invalid_boundary_rejected("valid_from", value)

    def test_falsy_invalid_valid_until_values_fail_closed(self):
        for value in (0, False, ""):
            with self.subTest(value=value):
                self._assert_invalid_boundary_rejected("valid_until", value)

    def test_canonical_aware_window_remains_current_inside_inclusive_bounds(self):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            valid_from=self.NOW - timedelta(minutes=1),
            valid_until=self.NOW + timedelta(minutes=1),
        )
        self.assertTrue(authorization.is_current(self.NOW))


if __name__ == "__main__":
    unittest.main()
