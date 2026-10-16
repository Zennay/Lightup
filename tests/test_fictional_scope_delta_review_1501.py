"""Ordinary stdlib regression tests for synthetic, non-authorizing #1501."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch

from lightup.fictional_scope_delta_review_1501 import (
    FictionalScopeProposal,
    ScopeDeltaReview,
    review_fictional_scope_delta,
)

T0 = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=3)


def proposal(**changes):
    record = FictionalScopeProposal(
        assets=("alpha.example.test", "beta.example.test"),
        capabilities=("headers_view", "metadata_view"),
        exclusions=(),
        risk=3,
        valid_from=T0,
        valid_until=T1,
    )
    return replace(record, **changes)


class FictionalScopeDeltaTests(TestCase):
    def assert_inert(self, result):
        self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"))
        self.assertIs(type(result), ScopeDeltaReview)
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_equal_proposals_are_review_only_never_approved(self):
        old = proposal()
        outcome = review_fictional_scope_delta(old, old)
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        self.assertEqual(outcome.expanded_dimensions, ())
        self.assertEqual(outcome.narrowed_dimensions, ())
        self.assert_inert(outcome)

    def test_every_independent_widening_holds(self):
        old = proposal(exclusions=("alpha.example.test",))
        changes = (
            ("assets", {"assets": ("alpha.example.test", "beta.example.test", "gamma.example.test")}),
            ("capabilities", {"capabilities": ("headers_view", "metadata_view", "tls_summary")}),
            ("exclusions", {"exclusions": ()}),
            ("risk", {"risk": 4}),
            ("valid_from", {"valid_from": T0 - timedelta(seconds=1)}),
            ("valid_until", {"valid_until": T1 + timedelta(seconds=1)}),
        )
        for reason, delta in changes:
            with self.subTest(reason=reason):
                outcome = review_fictional_scope_delta(old, replace(old, **delta))
                self.assertEqual(outcome.status, "HOLD")
                self.assertEqual(outcome.expanded_dimensions, (reason,))
                self.assertEqual(outcome.narrowed_dimensions, ())
                self.assert_inert(outcome)

    def test_every_independent_narrowing_is_review_only(self):
        old = proposal()
        changes = (
            ("assets", {"assets": ("alpha.example.test",)}),
            ("capabilities", {"capabilities": ("headers_view",)}),
            ("exclusions", {"exclusions": ("alpha.example.test",)}),
            ("risk", {"risk": 2}),
            ("valid_from", {"valid_from": T0 + timedelta(seconds=1)}),
            ("valid_until", {"valid_until": T1 - timedelta(seconds=1)}),
        )
        for reason, delta in changes:
            with self.subTest(reason=reason):
                outcome = review_fictional_scope_delta(old, replace(old, **delta))
                self.assertEqual(outcome.status, "REVIEW_ONLY")
                self.assertEqual(outcome.narrowed_dimensions, (reason,))
                self.assertEqual(outcome.expanded_dimensions, ())
                self.assert_inert(outcome)

    def test_multiple_expansions_are_atomic_hold_without_source_echo(self):
        outcome = review_fictional_scope_delta(
            proposal(),
            proposal(
                assets=("alpha.example.test", "gamma.example.test"),
                capabilities=("headers_view", "tls_summary"),
                risk=5,
            ),
        )
        self.assertEqual(outcome.status, "HOLD")
        self.assertEqual(outcome.expanded_dimensions, ("assets", "capabilities", "risk"))
        self.assertNotIn("gamma.example.test", repr(outcome))
        self.assert_inert(outcome)

    def test_multiple_narrowings_sorted_canonically(self):
        outcome = review_fictional_scope_delta(
            proposal(),
            proposal(
                assets=("alpha.example.test",),
                capabilities=("headers_view",),
                risk=1,
                valid_from=T0 + timedelta(hours=1),
                valid_until=T1 - timedelta(hours=1),
            ),
        )
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        self.assertEqual(
            outcome.narrowed_dimensions,
            ("assets", "capabilities", "risk", "valid_from", "valid_until"),
        )

    def test_invalid_values_fail_closed_without_identifiers(self):
        invalid = (
            {"assets": ["alpha.example.test"]},
            {"assets": ("evil.com",)},
            {"assets": ("alpha.example.test", "alpha.example.test")},
            {"assets": ("beta.example.test", "alpha.example.test")},
            {"assets": ("éxample.example.test",)},
            {"assets": ("Alpha.example.test",)},
            {"assets": ("alpha..example.test",)},
            {"assets": ("-alpha.example.test",)},
            {"assets": ("x" * 10000 + ".example.test",)},
            {"assets": tuple(f"a{i:02}.example.test" for i in range(17))},
            {"assets": ()},
            {"capabilities": ()},
            {"capabilities": ["headers_view"]},
            {"capabilities": ("active_scan",)},
            {"capabilities": ("headers_view", "headers_view")},
            {"exclusions": ("gamma.example.test",)},
            {"risk": True},
            {"risk": 0},
            {"risk": 6},
            {"risk": 3.0},
            {"valid_from": T0.replace(tzinfo=None)},
            {"valid_from": T0.replace(tzinfo=timezone(timedelta(hours=1)))},
            {"valid_from": T0.replace(microsecond=1)},
            {"valid_from": T1},
            {"valid_until": T0},
            {"valid_until": T1 + timedelta(days=32)},
        )
        for delta in invalid:
            with self.subTest(delta=str(delta)[:90]):
                bad = proposal(**delta)
                for first, second in ((bad, proposal()), (proposal(), bad)):
                    result = review_fictional_scope_delta(first, second)
                    self.assertEqual(result.status, "HOLD")
                    self.assertEqual(result.expanded_dimensions, ())
                    self.assertEqual(result.narrowed_dimensions, ())
                    self.assertNotIn("evil.com", repr(result))
                    self.assert_inert(result)

    def test_subclasses_and_type_confusion_fail_closed(self):
        class CustomProposal(FictionalScopeProposal):
            pass

        class CustomString(str):
            pass

        class CustomInt(int):
            pass

        class CustomDateTime(datetime):
            pass

        class CustomTuple(tuple):
            pass

        for bad in (
            CustomProposal(("alpha.example.test",), ("headers_view",), (), 1, T0, T1),
            proposal(assets=CustomTuple(("alpha.example.test",))),
            proposal(assets=(CustomString("alpha.example.test"),)),
            proposal(risk=CustomInt(3)),
            proposal(valid_from=CustomDateTime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)),
        ):
            with self.subTest(type=type(bad).__name__):
                self.assertEqual(review_fictional_scope_delta(proposal(), bad).status, "HOLD")

    def test_untrusted_object_never_coerced_or_invoked(self):
        class Trap:
            def __getattr__(self, name):
                raise AssertionError(f"untrusted attribute access: {name}")

            def __str__(self):
                raise AssertionError("unexpected conversion")

        result = review_fictional_scope_delta(Trap(), proposal())
        self.assertEqual(result.status, "HOLD")
        self.assert_inert(result)

    def test_returned_records_are_immutable(self):
        result = review_fictional_scope_delta(proposal(), proposal())
        with self.assertRaises(FrozenInstanceError):
            result.authorized = True
        with self.assertRaises(FrozenInstanceError):
            result.status = "APPROVED"
        with self.assertRaises(FrozenInstanceError):
            proposal().risk = 7
        with self.assertRaises(ValueError):
            ScopeDeltaReview("REVIEW_ONLY", ("risk",), ())
        with self.assertRaises(TypeError):
            ScopeDeltaReview("HOLD", (), (), authorized=True)
        with self.assertRaises(ValueError):
            ScopeDeltaReview("APPROVED", (), ())

    def test_pure_review_does_not_touch_external_boundaries(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("os.open", side_effect=AssertionError("os")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertEqual(review_fictional_scope_delta(proposal(), proposal()).status, "REVIEW_ONLY")
            self.assertEqual(review_fictional_scope_delta(proposal(), proposal(risk=5)).status, "HOLD")

    def test_exact_31_day_boundary_and_source_immutability(self):
        old = proposal(valid_until=T0 + timedelta(days=31))
        same = proposal(valid_until=T0 + timedelta(days=31))
        before = repr((old, same))
        result = review_fictional_scope_delta(old, same)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(repr((old, same)), before)
        too_long = proposal(valid_until=T0 + timedelta(days=31, seconds=1))
        self.assertEqual(review_fictional_scope_delta(old, too_long).status, "HOLD")
        self.assert_inert(result)

    def test_nonboolean_proof_flags_cannot_be_constructed(self):
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                ScopeDeltaReview("HOLD", (), (), **{field: True})

    def test_many_deterministic_widening_cases_do_not_approve(self):
        old = proposal()
        for index in range(256):
            with self.subTest(index=index):
                name = f"x{index:03}.example.test"
                changed = proposal(assets=("alpha.example.test", "beta.example.test", name))
                outcome = review_fictional_scope_delta(old, changed)
                self.assertEqual(outcome.status, "HOLD")
                self.assert_inert(outcome)


if __name__ == "__main__":
    import unittest
    unittest.main()
