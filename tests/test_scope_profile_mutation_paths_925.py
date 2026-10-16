"""#925 passive profile: prevent alternate public collection mutation bypasses.

This test suite is acceptance-only, stacked on unchanged source owner PR #175.
It never calls discovery collectors, targets, DNS, network or scanners.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


def signal(*, public: bool = True, active: bool = False) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.CONFIGURATION,
        summary="Fictional only: no target interaction",
        source="https://docs.example.test/",
        confidence=0.5,
        public_source=public,
        requires_target_interaction=active,
    )


def populated_profile() -> tuple[ProspectProfile, ProspectSignal]:
    p = ProspectProfile("synthetic-925", "Fictional Organization")
    first = signal()
    p.add_signal(first)
    return p, first


class PublicCollectionMutationSourceRED925(unittest.TestCase):
    def assert_public_mutation_rejected(self, mutator) -> None:
        p, first = populated_profile()
        before = tuple(p.signals)
        with self.assertRaises((AttributeError, TypeError)):
            mutator(p)
        self.assertEqual(tuple(p.signals), before)
        self.assertIs(tuple(p.signals)[0], first)

    def test_normal_add_signal_still_permits_valid_public_metadata(self) -> None:
        p, first = populated_profile()
        second = signal()
        p.add_signal(second)
        self.assertEqual(tuple(p.signals), (first, second))

    def test_existing_bad_add_signal_preserves_prior_snapshot(self) -> None:
        p, first = populated_profile()
        before = tuple(p.signals)
        with self.assertRaises(PermissionError):
            p.add_signal(signal(public=False))
        self.assertEqual(tuple(p.signals), before)
        self.assertIs(tuple(p.signals)[0], first)

    @unittest.expectedFailure
    def test_public_extend_must_not_bypass_validation(self) -> None:
        self.assert_public_mutation_rejected(
            lambda p: p.signals.extend((signal(public=False),))
        )

    @unittest.expectedFailure
    def test_public_insert_must_not_bypass_validation(self) -> None:
        self.assert_public_mutation_rejected(
            lambda p: p.signals.insert(0, signal(active=True))
        )

    @unittest.expectedFailure
    def test_public_clear_must_not_erase_validated_snapshot(self) -> None:
        self.assert_public_mutation_rejected(lambda p: p.signals.clear())

    @unittest.expectedFailure
    def test_public_pop_must_not_erase_validated_snapshot(self) -> None:
        self.assert_public_mutation_rejected(lambda p: p.signals.pop())

    @unittest.expectedFailure
    def test_public_slice_assignment_must_not_bypass_admission(self) -> None:
        def mutate(p: ProspectProfile) -> None:
            p.signals[:] = [signal(public=False)]
        self.assert_public_mutation_rejected(mutate)

    @unittest.expectedFailure
    def test_public_augmented_assignment_must_not_replace_snapshot(self) -> None:
        def mutate(p: ProspectProfile) -> None:
            p.signals += (signal(active=True),)
        self.assert_public_mutation_rejected(mutate)


if __name__ == "__main__":
    unittest.main()
