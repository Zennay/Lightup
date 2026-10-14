"""Expected-RED direct-grant time-boundary canaries for issue #738.

All inputs are synthetic, in-memory and inert.  Production owner #100 retains
ownership of engagements.py.  expectedFailure means a known security invariant
is NOT enforced; it must not count as permission to deploy or scan.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)


class _ComparisonSplicingDatetime(datetime):
    """Malicious datetime subclass: claims both directions are always in-range."""

    def __le__(self, other):
        return True

    def __ge__(self, other):
        return True


def _grant(start, end):
    return AuthorizationGrant(
        grant_id="synthetic-grant",
        client_id="synthetic-client",
        engagement_id="synthetic-engagement",
        approved_by="operator@example.test",
        reference="synthetic-only-not-consent",
        scope=ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=start,
        valid_until=end,
    )


class DirectGrantDatetimeIdentityTests(unittest.TestCase):
    def test_exact_builtin_valid_window_is_current(self):
        self.assertTrue(_grant(NOW - timedelta(seconds=1), NOW + timedelta(seconds=1)).is_current(NOW))

    def test_exact_builtin_future_window_denied(self):
        self.assertFalse(_grant(NOW + timedelta(days=1), NOW + timedelta(days=2)).is_current(NOW))

    def test_exact_builtin_expired_window_denied(self):
        self.assertFalse(_grant(NOW - timedelta(days=2), NOW - timedelta(days=1)).is_current(NOW))

    def test_exact_builtin_start_boundary_inclusive(self):
        self.assertTrue(_grant(NOW, NOW + timedelta(seconds=1)).is_current(NOW))

    def test_exact_builtin_end_boundary_inclusive(self):
        self.assertTrue(_grant(NOW - timedelta(seconds=1), NOW).is_current(NOW))

    def test_naive_evaluation_time_refused(self):
        grant = _grant(NOW - timedelta(days=1), NOW + timedelta(days=1))
        with self.assertRaises(ValueError):
            grant.is_current(NOW.replace(tzinfo=None))

    def test_canonical_future_direct_execution_policy_denied(self):
        grant = _grant(NOW + timedelta(days=1), NOW + timedelta(days=2))
        # ExecutionPolicy uses the real current clock, not NOW, so use wide future dates.
        distant = datetime.now(timezone.utc) + timedelta(days=200)
        grant = _grant(distant, distant + timedelta(days=1))
        self.assertFalse(_target_decision(grant).allowed)

    @unittest.expectedFailure
    def test_red_future_lower_bound_polymorphic_datetime_must_fail_closed(self):
        start = _ComparisonSplicingDatetime(2026, 10, 15, 12, tzinfo=timezone.utc)
        grant = _grant(start, NOW + timedelta(days=2))
        self.assertFalse(grant.is_current(NOW), "subclassed not-before boundary must not grant access")

    @unittest.expectedFailure
    def test_red_expired_upper_bound_polymorphic_datetime_must_fail_closed(self):
        end = _ComparisonSplicingDatetime(2026, 10, 13, 12, tzinfo=timezone.utc)
        grant = _grant(NOW - timedelta(days=2), end)
        self.assertFalse(grant.is_current(NOW), "subclassed expiry must not grant access")

    @unittest.expectedFailure
    def test_red_both_polymorphic_datetime_bounds_must_fail_closed(self):
        start = _ComparisonSplicingDatetime(2026, 10, 15, 12, tzinfo=timezone.utc)
        end = _ComparisonSplicingDatetime(2026, 10, 13, 12, tzinfo=timezone.utc)
        self.assertFalse(_grant(start, end).is_current(NOW))

    @unittest.expectedFailure
    def test_red_future_subclass_is_rejected_by_live_execution_policy(self):
        future = datetime.now(timezone.utc) + timedelta(days=200)
        start = _ComparisonSplicingDatetime(
            future.year, future.month, future.day, future.hour, future.minute,
            future.second, future.microsecond, tzinfo=timezone.utc
        )
        grant = _grant(start, future + timedelta(days=1))
        self.assertFalse(_target_decision(grant).allowed)

    @unittest.expectedFailure
    def test_red_expired_subclass_is_rejected_by_live_execution_policy(self):
        past = datetime.now(timezone.utc) - timedelta(days=200)
        end = _ComparisonSplicingDatetime(
            past.year, past.month, past.day, past.hour, past.minute,
            past.second, past.microsecond, tzinfo=timezone.utc
        )
        grant = _grant(past - timedelta(days=1), end)
        self.assertFalse(_target_decision(grant).allowed)

    def test_fixture_has_no_network_or_file_target_side_effects(self):
        grant = _grant(NOW - timedelta(days=1), NOW + timedelta(days=1))
        before = repr(grant)
        self.assertTrue(grant.is_current(NOW))
        self.assertEqual(repr(grant), before)


def _target_decision(grant):
    # Pure policy decision only. No ToolExecutor, handler, DNS, socket or scan.
    return ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="fixture.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=grant,
        )
    )


if __name__ == "__main__":
    unittest.main()
