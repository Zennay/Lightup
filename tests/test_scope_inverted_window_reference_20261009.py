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

    def test_naive_stored_start_currently_raises_type_error(self):
        # Characterization: caller must not mistake an exception for a denial.
        grant = self.grant(self.anchor.replace(tzinfo=None),
                           self.anchor + timedelta(days=1))
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_naive_stored_end_currently_raises_type_error(self):
        grant = self.grant(self.anchor - timedelta(days=1),
                           self.anchor.replace(tzinfo=None))
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_scope_decision_propagates_naive_grant_exception(self):
        # Identifies an integration fail-closed requirement; no network I/O.
        now = datetime.now(timezone.utc)
        grant = self.grant(now.replace(tzinfo=None), None)
        with self.assertRaises(TypeError):
            self.policy.decide(Target("https://authorized.example", authorization=grant))

    def test_start_only_bound_enforces_future_but_no_end(self):
        grant = self.grant(self.anchor)
        self.assertFalse(grant.is_current(self.anchor - timedelta(microseconds=1)))
        self.assertTrue(grant.is_current(self.anchor))
        self.assertTrue(grant.is_current(self.anchor + timedelta(days=365)))

    def test_end_only_bound_enforces_expiration_but_no_start(self):
        grant = self.grant(end=self.anchor)
        self.assertTrue(grant.is_current(self.anchor - timedelta(days=365)))
        self.assertTrue(grant.is_current(self.anchor))
        self.assertFalse(grant.is_current(self.anchor + timedelta(microseconds=1)))

    def test_unbounded_synthetic_grant_is_current_but_not_real_consent(self):
        grant = self.grant()
        self.assertTrue(grant.is_current(self.anchor))
        self.assertTrue(grant.is_current(self.anchor + timedelta(days=365)))

    def test_malformed_string_start_currently_raises_type_error(self):
        # Stored deserialization error must not be interpreted as approval.
        grant = self.grant("2026-10-09T12:00:00Z", None)
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_malformed_string_end_currently_raises_type_error(self):
        grant = self.grant(None, "2026-10-09T12:00:00Z")
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_public_scope_propagates_malformed_string_start(self):
        grant = self.grant("invalid-datetime", None)
        with self.assertRaises(TypeError):
            self.policy.decide(Target("https://authorized.example", authorization=grant))

    def test_out_of_scope_host_does_not_evaluate_malformed_grant(self):
        # Check scope before grant parsing; unrelated target must remain denied.
        grant = self.grant("invalid-timestamp", None)
        decision = self.policy.decide(Target("https://not-approved.example", authorization=grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_missing_public_grant_remains_denied_independent_of_clock(self):
        for address in ("authorized.example", "https://authorized.example/path"):
            with self.subTest(address=address):
                decision = self.policy.decide(Target(address))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_boolean_start_is_not_a_valid_datetime(self):
        # Legacy behavior: bad persisted type raises; owner must fail closed.
        grant = self.grant(True, None)
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_integer_end_is_not_a_valid_datetime(self):
        grant = self.grant(None, 42)
        with self.assertRaises(TypeError):
            grant.is_current(self.anchor)

    def test_public_scope_propagates_integer_end_type_error(self):
        grant = self.grant(None, 42)
        with self.assertRaises(TypeError):
            self.policy.decide(Target("https://authorized.example", authorization=grant))

    def test_falsy_malformed_start_is_silently_treated_as_unbounded(self):
        # Existing behavior is unsafe as production permission evidence.
        for bad in (0, False, ""):
            with self.subTest(bad=bad):
                self.assertTrue(self.grant(bad, None).is_current(self.anchor))

    def test_falsy_malformed_end_is_silently_treated_as_unbounded(self):
        for bad in (0, False, ""):
            with self.subTest(bad=bad):
                self.assertTrue(self.grant(None, bad).is_current(self.anchor))

    def test_falsy_malformed_start_passes_public_scope_legacy_gate(self):
        # Red-flag characterization, NOT permission to execute a target.
        grant = self.grant(False, None)
        decision = self.policy.decide(Target("https://authorized.example", authorization=grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_falsy_malformed_end_passes_public_scope_legacy_gate(self):
        # Demonstrates the impact at the actual policy boundary, offline only.
        grant = self.grant(None, "")
        decision = self.policy.decide(Target("https://authorized.example", authorization=grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_out_of_scope_stays_denied_despite_falsy_malformed_grant(self):
        grant = self.grant(False, "")
        decision = self.policy.decide(Target("https://unknown.example", authorization=grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_all_falsy_corrupt_bounds_pass_legacy_host_gate(self):
        # Characterization only: this must not be used as execution permission.
        for corrupt in (0, False, ""):
            for side in ("start", "end"):
                with self.subTest(corrupt=repr(corrupt), side=side):
                    grant = (self.grant(corrupt, None) if side == "start"
                             else self.grant(None, corrupt))
                    decision = self.policy.decide(
                        Target("https://authorized.example", authorization=grant))
                    self.assertTrue(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_falsy_corrupt_bounds_cannot_override_public_host_allowlist(self):
        for corrupt in (0, False, ""):
            with self.subTest(corrupt=repr(corrupt)):
                decision = self.policy.decide(
                    Target("https://unlisted.example",
                           authorization=self.grant(corrupt, corrupt)))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_falsy_corrupt_bounds_pass_legacy_public_network_gate(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        for corrupt in (0, False, ""):
            with self.subTest(corrupt=repr(corrupt)):
                decision = policy.decide(
                    Target("https://8.8.8.8", authorization=self.grant(corrupt, None)))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_falsy_corrupt_bounds_cannot_expand_public_network_allowlist(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        decision = policy.decide(
            Target("https://1.1.1.1", authorization=self.grant(False, "")))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

if __name__ == "__main__":
    unittest.main()
