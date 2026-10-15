"""Legacy authorization falsey-boundary expected-RED acceptance (#301).

No production changes, active targets, network, database, or dispatch. The
source owners of legacy Authorization in PR #100/#104 keep all production edits.
"""
import os
import random
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

    @unittest.expectedFailure
    def test_red_zero_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=0).is_current(NOW))

    @unittest.expectedFailure
    def test_red_false_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=False).is_current(NOW))

    @unittest.expectedFailure
    def test_red_empty_text_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end="").is_current(NOW))

    @unittest.expectedFailure
    def test_red_empty_tuple_expiry_is_not_unbounded(self):
        self.assertFalse(_authorization(end=()).is_current(NOW))

    @unittest.expectedFailure
    def test_red_zero_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=0).is_current(NOW))

    @unittest.expectedFailure
    def test_red_false_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=False).is_current(NOW))

    @unittest.expectedFailure
    def test_red_empty_text_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start="").is_current(NOW))

    @unittest.expectedFailure
    def test_red_empty_tuple_start_is_not_unbounded(self):
        self.assertFalse(_authorization(start=()).is_current(NOW))

    @unittest.expectedFailure
    def test_red_false_expiry_must_not_authorize_scope(self):
        decision = _pure_scope_decision(_authorization(end=False))
        self.assertFalse(decision.allowed)

    @unittest.expectedFailure
    def test_red_zero_expiry_must_not_authorize_scope(self):
        decision = _pure_scope_decision(_authorization(end=0))
        self.assertFalse(decision.allowed)

    def test_all_inputs_remain_unchanged_after_pure_scope_decision(self):
        # Unlike is_current(NOW) tests, ScopePolicy.decide() uses the real UTC
        # clock. The fixed 2026-10-14 fixture expires in real time and must
        # not make this positive immutability test fail on later CI runs.
        current_utc = datetime.now(timezone.utc)
        a = _authorization(
            start=current_utc - timedelta(days=1),
            end=current_utc + timedelta(days=1),
        )
        before = repr(a)
        self.assertTrue(_pure_scope_decision(a).allowed)
        self.assertEqual(repr(a), before)

    def test_scope_decision_stays_pure_across_exact_expiry_transition(self):
        # Mock only the legacy model's wall-clock provider. This exercises the
        # real ScopePolicy -> Authorization path, not an Authorization stub.
        # The fixed NOW constant remains appropriate for explicit-clock tests.
        grant = _authorization(
            start=NOW - timedelta(minutes=1),
            end=NOW + timedelta(minutes=1),
        )
        original = repr(grant)
        cases = (
            (NOW - timedelta(minutes=1, microseconds=1), False,
             ScopeReason.AUTHORIZATION_EXPIRED),
            (NOW - timedelta(minutes=1), True, ScopeReason.EXPLICIT_HOST),
            (NOW, True, ScopeReason.EXPLICIT_HOST),
            (NOW + timedelta(minutes=1), True, ScopeReason.EXPLICIT_HOST),
            (NOW + timedelta(minutes=1, microseconds=1), False,
             ScopeReason.AUTHORIZATION_EXPIRED),
        )
        for instant, expected_allowed, expected_reason in cases:
            with self.subTest(at=instant.isoformat()), patch(
                "lightup.models.datetime"
            ) as model_datetime:
                model_datetime.now.return_value = instant
                decision = _pure_scope_decision(grant)
                self.assertIs(decision.allowed, expected_allowed)
                self.assertEqual(decision.reason, expected_reason)
                self.assertEqual(decision.normalized_host,
                                 "scope.fixture.example.test")
                model_datetime.now.assert_called_once_with(timezone.utc)
                self.assertEqual(repr(grant), original)

    def test_randomized_out_of_order_scope_decisions_never_cache_authority(self):
        # Reusing one in-memory Authorization across hundreds of clock changes
        # must not let a previous allowed decision override an expired one.
        # All instants and shuffles are deterministic; no actual time is read.
        grant = _authorization(
            start=NOW - timedelta(seconds=60),
            end=NOW + timedelta(seconds=60),
        )
        initial = repr(grant)
        offsets = list(range(-150, 151)) * 2
        offsets.extend((-61, -60, 0, 60, 61) * 8)
        random.Random(301).shuffle(offsets)
        with patch("lightup.models.datetime") as model_datetime:
            for delta in offsets:
                model_datetime.now.return_value = NOW + timedelta(seconds=delta)
                decision = _pure_scope_decision(grant)
                expected = -60 <= delta <= 60
                self.assertIs(decision.allowed, expected)
                self.assertEqual(
                    decision.reason,
                    ScopeReason.EXPLICIT_HOST if expected
                    else ScopeReason.AUTHORIZATION_EXPIRED,
                )
                self.assertEqual(decision.normalized_host,
                                 "scope.fixture.example.test")
            self.assertEqual(model_datetime.now.call_count, len(offsets))
            self.assertEqual(repr(grant), initial)

    def test_expired_scope_decision_does_not_mutate_authorization(self):
        current_utc = datetime.now(timezone.utc)
        a = _authorization(
            start=current_utc - timedelta(days=2),
            end=current_utc - timedelta(days=1),
        )
        before = repr(a)
        decision = _pure_scope_decision(a)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        self.assertEqual(repr(a), before)


if __name__ == "__main__":
    unittest.main()
