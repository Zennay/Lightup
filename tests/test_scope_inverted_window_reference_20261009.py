"""Offline characterization of inverted and boundary authorization windows.

Synthetic Authorization instances are not authenticated approvals.
"""
from datetime import datetime, timedelta, timezone
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class InvertedAuthorizationWindowTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(explicit_hosts=frozenset({"authorized.example"}))
        self.anchor = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)

    def grant(self, start=None, end=None):
        return Authorization(
            owner="synthetic-owner",
            reference="offline-only-not-consent",
            valid_from=start,
            valid_until=end,
        )

    def test_inverted_window_never_current_before_or_after(self):
        grant = self.grant(self.anchor + timedelta(days=1),
                           self.anchor - timedelta(days=1))
        for candidate in (self.anchor - timedelta(days=2), self.anchor,
                          self.anchor + timedelta(days=2)):
            with self.subTest(candidate=candidate):
                self.assertFalse(grant.is_current(candidate))

    def test_exact_start_and_end_are_current_for_valid_window(self):
        start = self.anchor - timedelta(hours=1)
        end = self.anchor + timedelta(hours=1)
        grant = self.grant(start, end)
        self.assertTrue(grant.is_current(start))
        self.assertTrue(grant.is_current(end))

    def test_just_outside_valid_window_is_expired(self):
        start = self.anchor - timedelta(hours=1)
        end = self.anchor + timedelta(hours=1)
        grant = self.grant(start, end)
        self.assertFalse(grant.is_current(start - timedelta(microseconds=1)))
        self.assertFalse(grant.is_current(end + timedelta(microseconds=1)))

    def test_public_host_missing_grant_is_denied(self):
        decision = self.policy.decide(Target("https://authorized.example"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_inverted_window_denied_for_public_host_now(self):
        now = datetime.now(timezone.utc)
        grant = self.grant(now + timedelta(days=1), now - timedelta(days=1))
        decision = self.policy.decide(Target("https://authorized.example", authorization=grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_out_of_scope_host_never_authorized_by_window(self):
        grant = self.grant(self.anchor - timedelta(days=1),
                           self.anchor + timedelta(days=1))
        decision = self.policy.decide(Target("https://other.example", authorization=grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_naive_now_is_rejected(self):
        grant = self.grant(self.anchor - timedelta(days=1),
                           self.anchor + timedelta(days=1))
        with self.assertRaises(ValueError):
            grant.is_current(self.anchor.replace(tzinfo=None))


    def test_zero_duration_window_is_valid_only_at_exact_instant(self):
        grant = self.grant(self.anchor, self.anchor)
        self.assertTrue(grant.is_current(self.anchor))
        self.assertFalse(grant.is_current(self.anchor - timedelta(microseconds=1)))
        self.assertFalse(grant.is_current(self.anchor + timedelta(microseconds=1)))

    def test_offset_aware_clock_is_compared_as_absolute_instant(self):
        from datetime import timezone as tz
        east = tz(timedelta(hours=5, minutes=30))
        instant = self.anchor.astimezone(east)
        grant = self.grant(self.anchor, self.anchor)
        self.assertTrue(grant.is_current(instant))

    def test_inverted_window_across_timezones_remains_denied(self):
        from datetime import timezone as tz
        east = tz(timedelta(hours=9))
        start = (self.anchor + timedelta(hours=1)).astimezone(east)
        end = self.anchor
        grant = self.grant(start, end)
        self.assertFalse(grant.is_current(self.anchor))
        self.assertFalse(grant.is_current(self.anchor + timedelta(hours=1)))

    def test_public_host_future_window_denied(self):
        now = datetime.now(timezone.utc)
        grant = self.grant(now + timedelta(days=1), now + timedelta(days=2))
        decision = self.policy.decide(Target("https://authorized.example", authorization=grant))
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        self.assertFalse(decision.allowed)

if __name__ == "__main__":
    unittest.main()
