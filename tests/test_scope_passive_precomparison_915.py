"""#915 pre-comparison proof: never invoke untrusted float overrides.

Supplement to the canonical confidence acceptance on source-owner #175.
Pure in-memory checks only; no active discovery, DNS, target or network I/O.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


COMPARE_CALLS: list[str] = []


class LoggedFloat(float):
    def __ge__(self, other: object) -> bool:
        COMPARE_CALLS.append("foreign-ge")
        return True

    def __le__(self, other: object) -> bool:
        COMPARE_CALLS.append("foreign-le")
        return True


class ThrowingFloat(float):
    def __ge__(self, other: object) -> bool:
        COMPARE_CALLS.append("throwing-ge")
        raise RuntimeError("untrusted rich comparison reached")

    def __le__(self, other: object) -> bool:
        COMPARE_CALLS.append("throwing-le")
        raise RuntimeError("untrusted rich comparison reached")


def signal(confidence: object) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.TECHNOLOGY,
        summary="Fictional offline documentation metadata",
        source="https://docs.example.test/",
        confidence=confidence,
        public_source=True,
        requires_target_interaction=False,
    )


class PrecomparisonSourceRED915(unittest.TestCase):
    def setUp(self) -> None:
        COMPARE_CALLS.clear()

    def tearDown(self) -> None:
        COMPARE_CALLS.clear()

    def test_exact_builtin_float_can_be_compared_without_foreign_hooks(self) -> None:
        profile = ProspectProfile("fictional-915-probe", "Synthetic")
        candidate = signal(0.5)
        profile.add_signal(candidate)
        self.assertEqual(tuple(profile.signals), (candidate,))
        self.assertEqual(COMPARE_CALLS, [])

    @unittest.expectedFailure
    def test_logged_float_must_be_rejected_before_comparison(self) -> None:
        profile = ProspectProfile("fictional-915-probe", "Synthetic")
        candidate = signal(LoggedFloat(0.5))
        before = tuple(profile.signals)
        with self.assertRaises(ValueError):
            profile.add_signal(candidate)
        self.assertEqual(COMPARE_CALLS, [])
        self.assertEqual(tuple(profile.signals), before)

    @unittest.expectedFailure
    def test_throwing_float_must_be_rejected_without_invoking_hook(self) -> None:
        profile = ProspectProfile("fictional-915-probe", "Synthetic")
        candidate = signal(ThrowingFloat(0.5))
        before = tuple(profile.signals)
        with self.assertRaises(ValueError):
            profile.add_signal(candidate)
        self.assertEqual(COMPARE_CALLS, [])
        self.assertEqual(tuple(profile.signals), before)


if __name__ == "__main__":
    unittest.main()
