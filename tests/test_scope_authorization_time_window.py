import os
import sys
import unittest
from dataclasses import fields
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class AuthorizationTimeWindowContractTests(unittest.TestCase):
    @staticmethod
    def authorization(**overrides):
        values = {
            "owner": "scope-time-owner",
            "reference": "AUTH-TIME-WINDOW",
            **overrides,
        }
        field_names = {item.name for item in fields(Authorization)}
        if "assets" in field_names and "assets" not in values:
            values["assets"] = ("security.example.test",)
        return Authorization(**values)

    def test_valid_from_boundary_is_inclusive(self):
        now = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        authorization = self.authorization(valid_from=now)
        self.assertTrue(authorization.is_current(now))

    def test_valid_until_boundary_is_inclusive(self):
        now = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        authorization = self.authorization(valid_until=now)
        self.assertTrue(authorization.is_current(now))

    def test_before_valid_from_and_after_valid_until_are_not_current(self):
        start = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        authorization = self.authorization(valid_from=start, valid_until=end)

        self.assertFalse(authorization.is_current(start - timedelta(microseconds=1)))
        self.assertFalse(authorization.is_current(end + timedelta(microseconds=1)))

    def test_equivalent_timezone_aware_instants_compare_consistently(self):
        utc_boundary = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        plus_two = timezone(timedelta(hours=2))
        equivalent_boundary = datetime(2026, 10, 6, 14, 0, tzinfo=plus_two)

        authorization = self.authorization(
            valid_from=equivalent_boundary,
            valid_until=equivalent_boundary,
        )
        self.assertTrue(authorization.is_current(utc_boundary))

    def test_timezone_naive_evaluation_instant_is_rejected(self):
        authorization = self.authorization()
        naive_now = datetime(2026, 10, 6, 12, 0)
        with self.assertRaises(ValueError):
            authorization.is_current(naive_now)

    def test_inverted_window_never_becomes_current(self):
        valid_until = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        valid_from = valid_until + timedelta(hours=1)
        authorization = self.authorization(
            valid_from=valid_from,
            valid_until=valid_until,
        )

        for now in (
            valid_until - timedelta(hours=1),
            valid_until,
            valid_until + timedelta(minutes=30),
            valid_from,
            valid_from + timedelta(hours=1),
        ):
            with self.subTest(now=now):
                self.assertFalse(authorization.is_current(now))

    def test_public_scope_denies_future_and_expired_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))
        now = datetime.now(timezone.utc)
        cases = {
            "future": self.authorization(valid_from=now + timedelta(hours=1)),
            "expired": self.authorization(valid_until=now - timedelta(hours=1)),
        }

        for name, authorization in cases.items():
            with self.subTest(name=name):
                decision = policy.decide(
                    Target("security.example.test", authorization=authorization)
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)


if __name__ == "__main__":
    unittest.main()
