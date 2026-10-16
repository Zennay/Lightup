"""Issue #915: source-owner RED acceptance for canonical passive confidence.

Tests/data only, pinned to PR #175 head
df9eac879bbe232cd1e50fd6e9dfe12ff38f8469.
No HTTP, DNS, discovery execution or live asset interaction.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class LyingFloat(float):
    """Outside the legal interval, but rich comparisons falsely say inside."""
    def __ge__(self, other: object) -> bool:
        return True

    def __le__(self, other: object) -> bool:
        return True


def signal(confidence: object) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.TECHNOLOGY,
        summary="Public fictional documentation only",
        source="https://docs.example.test/",
        confidence=confidence,
        public_source=True,
        requires_target_interaction=False,
    )


def profile() -> ProspectProfile:
    p = ProspectProfile(
        prospect_id="fictional-prospect-915",
        organization_name="Fictional Organization",
    )
    p.add_signal(signal(0.5))
    return p


class CanonicalConfidenceControls915(unittest.TestCase):
    def test_exact_zero(self) -> None:
        p = profile()
        p.add_signal(signal(0.0))
        self.assertEqual(len(p.signals), 2)
        self.assertEqual(p.confidence, 0.25)

    def test_exact_interior(self) -> None:
        p = profile()
        p.add_signal(signal(0.75))
        self.assertEqual(len(p.signals), 2)
        self.assertEqual(p.confidence, 0.625)

    def test_exact_one(self) -> None:
        p = profile()
        p.add_signal(signal(1.0))
        self.assertEqual(len(p.signals), 2)
        self.assertEqual(p.confidence, 0.75)

    def test_exact_float_underflow_is_rejected_atomically(self) -> None:
        p = profile()
        before = tuple(p.signals)
        with self.assertRaises(ValueError):
            p.add_signal(signal(-0.0001))
        self.assertEqual(tuple(p.signals), before)

    def test_exact_float_overflow_is_rejected_atomically(self) -> None:
        p = profile()
        before = tuple(p.signals)
        with self.assertRaises(ValueError):
            p.add_signal(signal(1.0001))
        self.assertEqual(tuple(p.signals), before)

    def test_nan_is_rejected_atomically(self) -> None:
        p = profile()
        before = tuple(p.signals)
        with self.assertRaises(ValueError):
            p.add_signal(signal(float("nan")))
        self.assertEqual(tuple(p.signals), before)


class CanonicalConfidenceOwnerRED915(unittest.TestCase):
    """Do not mistake expected failures for fixed production validation."""

    def require_exact_float(self, marker: object) -> None:
        p = profile()
        old_snapshot = tuple(p.signals)
        candidate = signal(marker)
        with self.assertRaises(ValueError):
            p.add_signal(candidate)
        self.assertEqual(tuple(p.signals), old_snapshot)
        self.assertIs(candidate.confidence, marker)

    @unittest.expectedFailure
    def test_boolean_true_must_be_rejected(self) -> None:
        self.require_exact_float(True)

    @unittest.expectedFailure
    def test_boolean_false_must_be_rejected(self) -> None:
        self.require_exact_float(False)

    @unittest.expectedFailure
    def test_integer_zero_must_be_rejected(self) -> None:
        self.require_exact_float(0)

    @unittest.expectedFailure
    def test_integer_one_must_be_rejected(self) -> None:
        self.require_exact_float(1)

    @unittest.expectedFailure
    def test_polymorphic_float_must_be_rejected_before_comparison(self) -> None:
        self.require_exact_float(LyingFloat(3.0))


if __name__ == "__main__":
    unittest.main()
