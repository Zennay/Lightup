"""Legacy authorization falsey-boundary expected-RED acceptance (#301).

No production changes, active targets, network, database, or dispatch. The
source owners of legacy Authorization in PR #100/#104 keep all production edits.
"""
import os
import random
import sys
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
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


def _pure_scope_decision_at(auth, instant, *, allow_preclock_denial=False):
    # Run installed scope and authorization code, replacing only the clock.
    # A strict source fix may reject malformed temporal fields BEFORE reading
    # the clock; valid-window tests still require exactly one aware UTC read.
    with patch("lightup.models.datetime") as model_datetime:
        model_datetime.now.return_value = instant
        decision = _pure_scope_decision(auth)
        if not (allow_preclock_denial and decision.allowed is False
                and model_datetime.now.call_count == 0):
            model_datetime.now.assert_called_once_with(timezone.utc)
        return decision


class _FalseyDatetimeSubclass(datetime):
    # Even a datetime-shaped polymorphic object may lie about truthiness.
    # Canonical legacy boundary values must use exact built-in datetime.
    def __bool__(self):
        return False


class _NullOffsetTimezone(tzinfo):
    # tzinfo is non-None but utcoffset() says this datetime is naive.
    def utcoffset(self, dt):
        return None

    def tzname(self, dt):
        return "NOT-A-REAL-TIMEZONE"

    def dst(self, dt):
        return None


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
        decision = _pure_scope_decision_at(
            _authorization(end=NOW - timedelta(days=30)), NOW
        )
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

    @unittest.expectedFailure
    def test_red_falsey_datetime_subclass_must_not_disable_future_start(self):
        future = NOW + timedelta(days=1)
        deceptive = _FalseyDatetimeSubclass(
            future.year, future.month, future.day,
            future.hour, future.minute, future.second,
            future.microsecond, tzinfo=timezone.utc,
        )
        self.assertFalse(_authorization(start=deceptive).is_current(NOW))

    @unittest.expectedFailure
    def test_red_falsey_datetime_subclass_must_not_disable_expired_end(self):
        expired = NOW - timedelta(days=1)
        deceptive = _FalseyDatetimeSubclass(
            expired.year, expired.month, expired.day,
            expired.hour, expired.minute, expired.second,
            expired.microsecond, tzinfo=timezone.utc,
        )
        self.assertFalse(_authorization(end=deceptive).is_current(NOW))

    @unittest.expectedFailure
    def test_red_falsey_datetime_subclass_cannot_open_public_scope_early(self):
        future = NOW + timedelta(days=1)
        deceptive = _FalseyDatetimeSubclass(
            future.year, future.month, future.day,
            future.hour, future.minute, future.second,
            future.microsecond, tzinfo=timezone.utc,
        )
        grant = _authorization(start=deceptive)
        original = repr(grant)
        decision = _pure_scope_decision_at(grant, NOW, allow_preclock_denial=True)
        self.assertEqual(decision.normalized_host,
                         "scope.fixture.example.test")
        self.assertEqual(repr(grant), original)
        self.assertFalse(decision.allowed, "future start must deny scope")

    @unittest.expectedFailure
    def test_red_falsey_datetime_subclass_cannot_open_public_scope_expired(self):
        expired = NOW - timedelta(days=1)
        deceptive = _FalseyDatetimeSubclass(
            expired.year, expired.month, expired.day,
            expired.hour, expired.minute, expired.second,
            expired.microsecond, tzinfo=timezone.utc,
        )
        grant = _authorization(end=deceptive)
        original = repr(grant)
        decision = _pure_scope_decision_at(grant, NOW, allow_preclock_denial=True)
        self.assertEqual(decision.normalized_host,
                         "scope.fixture.example.test")
        self.assertEqual(repr(grant), original)
        self.assertFalse(decision.allowed, "expired end must deny scope")

    def test_installed_source_really_allows_falsey_boundaries_without_errors(self):
        # Ordinary PASS evidence of the actual installed security fault.
        # An unexpected TypeError/ValueError is NOT an acceptable substitute
        # for observing unauthorized True results in the expected-RED tests.
        future = NOW + timedelta(days=1)
        expired = NOW - timedelta(days=1)
        deceptive_future = _FalseyDatetimeSubclass(
            future.year, future.month, future.day,
            future.hour, future.minute, future.second,
            future.microsecond, tzinfo=timezone.utc,
        )
        deceptive_expired = _FalseyDatetimeSubclass(
            expired.year, expired.month, expired.day,
            expired.hour, expired.minute, expired.second,
            expired.microsecond, tzinfo=timezone.utc,
        )
        values = (0, False, "", (), deceptive_future, deceptive_expired)
        for position in ("start", "end"):
            for value in values:
                if isinstance(value, _FalseyDatetimeSubclass):
                    # A future start and a past end are the only deliberately
                    # invalid subclass scenarios (the opposite would be valid).
                    if position == "start" and value is deceptive_expired:
                        continue
                    if position == "end" and value is deceptive_future:
                        continue
                with self.subTest(position=position, value=repr(value)):
                    grant = _authorization(
                        start=value if position == "start" else None,
                        end=value if position == "end" else None,
                    )
                    before = repr(grant)
                    self.assertIs(
                        grant.is_current(NOW), True,
                        "installed source must exhibit the known bypass",
                    )
                    self.assertEqual(repr(grant), before)

    def test_installed_public_scope_really_allows_falsey_boundaries(self):
        # Prove the actual public gate is incorrectly OPEN on four distinct
        # values rather than treating an unrelated exception as a source RED.
        expired = NOW - timedelta(days=1)
        deceptive_expired = _FalseyDatetimeSubclass(
            expired.year, expired.month, expired.day,
            expired.hour, expired.minute, expired.second,
            expired.microsecond, tzinfo=timezone.utc,
        )
        future = NOW + timedelta(days=1)
        deceptive_future = _FalseyDatetimeSubclass(
            future.year, future.month, future.day,
            future.hour, future.minute, future.second,
            future.microsecond, tzinfo=timezone.utc,
        )
        candidates = (
            ("end_false", _authorization(end=False)),
            ("end_zero", _authorization(end=0)),
            ("start_falsey_subclass", _authorization(start=deceptive_future)),
            ("end_falsey_subclass", _authorization(end=deceptive_expired)),
        )
        for name, grant in candidates:
            with self.subTest(candidate=name):
                before = repr(grant)
                decision = _pure_scope_decision_at(grant, NOW)
                self.assertIs(
                    decision.allowed, True,
                    "actual source gate must expose the known bypass",
                )
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
                self.assertEqual(
                    decision.normalized_host, "scope.fixture.example.test"
                )
                self.assertEqual(repr(grant), before)

    def test_installed_naive_boundaries_raise_instead_of_explicitly_denial(self):
        # Source must not silently be credited with an AUTHORIZATION_EXPIRED
        # denial when it actually raises a Python mixed-aware comparison.
        naive_future = (NOW + timedelta(days=1)).replace(tzinfo=None)
        naive_expired = (NOW - timedelta(days=1)).replace(tzinfo=None)
        pseudo_future = (NOW + timedelta(days=1)).replace(
            tzinfo=_NullOffsetTimezone()
        )
        pseudo_expired = (NOW - timedelta(days=1)).replace(
            tzinfo=_NullOffsetTimezone()
        )
        for position, value in (
            ("start", naive_future), ("end", naive_expired),
            ("start", pseudo_future), ("end", pseudo_expired),
        ):
            with self.subTest(position=position, boundary=repr(value)):
                grant = _authorization(
                    start=value if position == "start" else None,
                    end=value if position == "end" else None,
                )
                before = repr(grant)
                with self.assertRaises(TypeError):
                    grant.is_current(NOW)
                with self.assertRaises(TypeError):
                    _pure_scope_decision_at(grant, NOW)
                self.assertEqual(repr(grant), before)

    @unittest.expectedFailure
    def test_red_naive_datetime_future_start_must_explicitly_deny(self):
        naive = (NOW + timedelta(days=1)).replace(tzinfo=None)
        self.assertIs(_authorization(start=naive).is_current(NOW), False)

    @unittest.expectedFailure
    def test_red_naive_datetime_expired_end_must_explicitly_deny(self):
        naive = (NOW - timedelta(days=1)).replace(tzinfo=None)
        self.assertIs(_authorization(end=naive).is_current(NOW), False)

    @unittest.expectedFailure
    def test_red_null_offset_timezone_future_start_must_explicitly_deny(self):
        pseudo = (NOW + timedelta(days=1)).replace(
            tzinfo=_NullOffsetTimezone()
        )
        self.assertIs(_authorization(start=pseudo).is_current(NOW), False)

    @unittest.expectedFailure
    def test_red_null_offset_timezone_expired_end_must_explicitly_deny(self):
        pseudo = (NOW - timedelta(days=1)).replace(
            tzinfo=_NullOffsetTimezone()
        )
        self.assertIs(_authorization(end=pseudo).is_current(NOW), False)

    @unittest.expectedFailure
    def test_red_naive_public_scope_must_explicitly_deny(self):
        pseudo = (NOW + timedelta(days=1)).replace(tzinfo=None)
        decision = _pure_scope_decision_at(
            _authorization(start=pseudo), NOW,
            allow_preclock_denial=True,
        )
        self.assertFalse(decision.allowed)

    @unittest.expectedFailure
    def test_red_null_offset_timezone_public_scope_must_explicitly_deny(self):
        pseudo = (NOW - timedelta(days=1)).replace(
            tzinfo=_NullOffsetTimezone()
        )
        decision = _pure_scope_decision_at(
            _authorization(end=pseudo), NOW,
            allow_preclock_denial=True,
        )
        self.assertFalse(decision.allowed)

    def test_reference_type_repair_flips_all_twenty_legacy_boundary_reds(self):
        # A test-only patch demonstrates that the installed-source RED tests
        # detect a missing exact-type guard, not merely a bad test fixture.
        # This reference repair does not modify LightUp's installed code.
        original = Authorization.is_current

        def reference_narrowing(authorization, now=None):
            for boundary in (
                authorization.valid_from, authorization.valid_until
            ):
                if boundary is not None and (
                    type(boundary) is not datetime or boundary.tzinfo is None
                    or boundary.utcoffset() is None
                ):
                    return False
            return original(authorization, now)

        red_methods = (
            "test_red_zero_expiry_is_not_unbounded",
            "test_red_false_expiry_is_not_unbounded",
            "test_red_empty_text_expiry_is_not_unbounded",
            "test_red_empty_tuple_expiry_is_not_unbounded",
            "test_red_zero_start_is_not_unbounded",
            "test_red_false_start_is_not_unbounded",
            "test_red_empty_text_start_is_not_unbounded",
            "test_red_empty_tuple_start_is_not_unbounded",
            "test_red_false_expiry_must_not_authorize_scope",
            "test_red_zero_expiry_must_not_authorize_scope",
            "test_red_falsey_datetime_subclass_must_not_disable_future_start",
            "test_red_falsey_datetime_subclass_must_not_disable_expired_end",
            "test_red_falsey_datetime_subclass_cannot_open_public_scope_early",
            "test_red_falsey_datetime_subclass_cannot_open_public_scope_expired",
            "test_red_naive_datetime_future_start_must_explicitly_deny",
            "test_red_naive_datetime_expired_end_must_explicitly_deny",
            "test_red_null_offset_timezone_future_start_must_explicitly_deny",
            "test_red_null_offset_timezone_expired_end_must_explicitly_deny",
            "test_red_naive_public_scope_must_explicitly_deny",
            "test_red_null_offset_timezone_public_scope_must_explicitly_deny",
        )
        with patch.object(Authorization, "is_current", reference_narrowing):
            for name in red_methods:
                with self.subTest(method=name):
                    test_case = type(self)(name)
                    result = unittest.TestResult()
                    test_case.run(result)
                    self.assertEqual(len(result.unexpectedSuccesses), 1)
                    self.assertEqual(result.expectedFailures, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.errors, [])
            canonical = _authorization(
                start=NOW - timedelta(seconds=1),
                end=NOW + timedelta(seconds=1),
            )
            self.assertTrue(canonical.is_current(NOW))
            decision = _pure_scope_decision_at(canonical, NOW)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_all_inputs_remain_unchanged_after_pure_scope_decision(self):
        # No CI calendar dependence: inject NOW through the real
        # ScopePolicy -> Authorization.is_current() wall-clock boundary.
        a = _authorization(
            start=NOW - timedelta(days=1),
            end=NOW + timedelta(days=1),
        )
        before = repr(a)
        decision = _pure_scope_decision_at(a, NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
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

    def test_calendar_year_shift_invariance_and_timezone_equivalence(self):
        # Each synthetic time window is evaluated at fixed, varied calendar
        # years. A successful historical fixture must not expire in CI simply
        # because the current calendar year has changed.
        for year in (2024, 2026, 2030, 2050, 2099):
            instant = datetime(year, 10, 14, 12, tzinfo=timezone.utc)
            grant = _authorization(
                start=instant - timedelta(minutes=5),
                end=instant + timedelta(minutes=5),
            )
            before = repr(grant)
            for offset in (
                timedelta(hours=-11), timedelta(hours=-5, minutes=-30),
                timedelta(0), timedelta(hours=5, minutes=45),
                timedelta(hours=14),
            ):
                equivalent_instant = instant.astimezone(timezone(offset))
                with self.subTest(year=year, offset=offset):
                    decision = _pure_scope_decision_at(
                        grant, equivalent_instant
                    )
                    self.assertIs(decision.allowed, True)
                    self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
                    self.assertEqual(repr(grant), before)
            for delta, expected_allowed in (
                (-301, False), (-300, True), (300, True), (301, False)
            ):
                with self.subTest(year=year, seconds=delta):
                    decision = _pure_scope_decision_at(
                        grant, instant + timedelta(seconds=delta)
                    )
                    self.assertIs(decision.allowed, expected_allowed)
                    self.assertEqual(
                        decision.reason,
                        ScopeReason.EXPLICIT_HOST if expected_allowed
                        else ScopeReason.AUTHORIZATION_EXPIRED,
                    )

    def test_repeated_multi_grant_clock_evaluations_never_replay_prior_scope(self):
        # Alternate independent fictional authorization records across time.
        # A previous admissible decision must not confer new authority on a
        # separate, not-yet-current or expired record.
        windows = (
            (-2, -1), (-1, 1), (1, 2), (-3, 3), (-4, -3),
        )
        grants = [
            _authorization(
                start=NOW + timedelta(days=start),
                end=NOW + timedelta(days=end),
            ) for start, end in windows
        ]
        before = tuple(map(repr, grants))
        events = [
            (index, day)
            for index in range(len(grants))
            for day in (-5, -3, -2, -1, 0, 1, 2, 3, 5)
        ] * 8
        random.Random(1301).shuffle(events)
        for index, day in events:
            start, end = windows[index]
            decision = _pure_scope_decision_at(
                grants[index], NOW + timedelta(days=day)
            )
            allowed = start <= day <= end
            self.assertIs(decision.allowed, allowed)
            self.assertEqual(
                decision.reason,
                ScopeReason.EXPLICIT_HOST if allowed
                else ScopeReason.AUTHORIZATION_EXPIRED,
            )
        self.assertEqual(tuple(map(repr, grants)), before)

    def test_expired_scope_decision_does_not_mutate_authorization(self):
        a = _authorization(
            start=NOW - timedelta(days=2),
            end=NOW - timedelta(days=1),
        )
        before = repr(a)
        decision = _pure_scope_decision_at(a, NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        self.assertEqual(repr(a), before)


if __name__ == "__main__":
    unittest.main()
