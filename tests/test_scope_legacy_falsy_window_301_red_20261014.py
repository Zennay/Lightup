"""Legacy authorization falsey-boundary acceptance (#301, formerly expected-RED).

No production changes, active targets, network, database, or dispatch. The
source owners of legacy Authorization in PR #100/#104 keep all production edits.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


def _authorization(*, start=None, end=None):
    return Authorization(
        owner="synthetic-operator@example.test",
        reference="NOT-A-CONSENT-REFERENCE",
        valid_from=start,
        valid_until=end,
    )


def _pure_scope_decision(auth):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset({"scope.fixture.example.test"}),
        require_authorization_for_public=True,
    ).decide(Target(value="scope.fixture.example.test", authorization=auth))


def _pure_scope_decision_at(auth, instant):
    """Exercise the installed scope gate at a fixed synthetic time, not wall time."""
    original_is_current = Authorization.is_current
    observed = []

    def at_instant(grant, now=None):
        if now is not None:
            raise AssertionError("unexpected scope-supplied time override")
        observed.append(grant)
        return original_is_current(grant, instant)

    with patch.object(Authorization, "is_current", at_instant):
        decision = _pure_scope_decision(auth)
    if len(observed) != 1 or observed[0] is not auth:
        raise AssertionError("scope did not evaluate the exact authorization once")
    return decision


class LegacyFalsyBoundaryRedTests(unittest.TestCase):
    def test_builtin_aware_valid_window(self):
        self.assertTrue(_authorization(start=NOW - timedelta(hours=1),
                                       end=NOW + timedelta(hours=1)).is_current(NOW))

    def test_builtin_aware_future_denied(self):
        self.assertFalse(_authorization(start=NOW + timedelta(hours=1)).is_current(NOW))

    def test_builtin_aware_expired_denied(self):
        self.assertFalse(_authorization(end=NOW - timedelta(hours=1)).is_current(NOW))

    def test_exact_start_inclusive(self):
        self.assertTrue(_authorization(start=NOW).is_current(NOW))

    def test_exact_end_inclusive(self):
        self.assertTrue(_authorization(end=NOW).is_current(NOW))

    def test_none_unbounded_legacy_reference_is_current(self):
        # This is a characterization, NOT a statement of customer consent.
        self.assertTrue(_authorization(start=None, end=None).is_current(NOW))

    def test_naive_evaluation_instant_refused(self):
        with self.assertRaises(ValueError):
            _authorization().is_current(NOW.replace(tzinfo=None))

    def test_canonical_expired_explicit_host_scope_denied(self):
        decision = _pure_scope_decision(_authorization(end=NOW - timedelta(days=30)))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_red_zero_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=0).is_current(NOW))

    def test_red_false_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=False).is_current(NOW))

    def test_red_empty_text_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end="").is_current(NOW))

    def test_red_empty_tuple_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=()).is_current(NOW))

    def test_red_zero_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=0).is_current(NOW))

    def test_red_false_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=False).is_current(NOW))

    def test_red_empty_text_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start="").is_current(NOW))

    def test_red_empty_tuple_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=()).is_current(NOW))

    def test_red_false_expiry_must_not_authorize_scope(self):
        decision = _pure_scope_decision(_authorization(end=False))
        self.assertFalse(decision.allowed)

    def test_red_zero_expiry_must_not_authorize_scope(self):
        decision = _pure_scope_decision(_authorization(end=0))
        self.assertFalse(decision.allowed)

    def test_all_inputs_remain_unchanged_after_pure_scope_decision(self):
        # Scope decisions use the live clock, so the window brackets real now.
        now = datetime.now(timezone.utc)
        a = _authorization(start=now - timedelta(days=1), end=now + timedelta(days=1))
        before = repr(a)
        self.assertTrue(_pure_scope_decision_at(a, NOW).allowed)
        self.assertEqual(repr(a), before)


if __name__ == "__main__":
    unittest.main()
