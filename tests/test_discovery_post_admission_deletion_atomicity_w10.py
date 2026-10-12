"""Issue #936 W10: profile deletion and alias-mutation atomicity, offline only.

This is an independent, acceptance-only test module above the immutable v9
composition. Expected-failure canaries expose the old mutable producer and
MUST be converted to ordinary passing tests by the source owner after repair.
No target, network, handler, scan or authorization grant is used.
"""
from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class PassiveDiscoveryPostAdmissionDeletionTest(unittest.TestCase):
    @staticmethod
    def signal(*, confidence: float = 0.8, interactive: bool = False,
               public: bool = True) -> ProspectSignal:
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Invented public metadata",
            source="local-synthetic-fixture",
            confidence=confidence,
            public_source=public,
            requires_target_interaction=interactive,
        )

    def admitted(self):
        profile = ProspectProfile("fixture-prospect", "Fixture Organisation")
        first = self.signal()
        profile.add_signal(first)
        return profile, first

    def assert_unchanged(self, profile, first):
        self.assertEqual(profile.prospect_id, "fixture-prospect")
        self.assertEqual(profile.organization_name, "Fixture Organisation")
        self.assertIs(type(profile.signals), tuple)
        self.assertEqual(profile.signals, (first,))
        self.assertEqual(profile.confidence, 0.8)

    @unittest.expectedFailure
    def test_del_prospect_id_cannot_erase_admitted_identity(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            del profile.prospect_id
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_del_organization_name_cannot_erase_admitted_identity(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            del profile.organization_name
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_del_signals_attribute_cannot_erase_admission(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            del profile.signals
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_del_signals_item_cannot_erase_admission(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            del profile.signals[0]
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_inplace_multiply_cannot_clear_admitted_signals(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            profile.signals *= 0
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_slice_replacement_cannot_inject_interactive_signal(self):
        profile, first = self.admitted()
        disallowed = self.signal(interactive=True)
        with self.assertRaises((AttributeError, TypeError)):
            profile.signals[:] = [disallowed]
        self.assert_unchanged(profile, first)
        self.assertTrue(disallowed.requires_target_interaction)

    @unittest.expectedFailure
    def test_extend_cannot_append_unvalidated_signal(self):
        profile, first = self.admitted()
        disallowed = self.signal(public=False)
        with self.assertRaises((AttributeError, TypeError)):
            profile.signals.extend([disallowed])
        self.assert_unchanged(profile, first)

    @unittest.expectedFailure
    def test_pop_cannot_remove_previously_admitted_signal(self):
        profile, first = self.admitted()
        with self.assertRaises((AttributeError, TypeError)):
            profile.signals.pop()
        self.assert_unchanged(profile, first)

    def test_repeated_rejected_signals_preserve_same_snapshot(self):
        profile, first = self.admitted()
        reference = tuple(profile.signals)
        for i in range(4):
            for disallowed in (self.signal(interactive=True), self.signal(public=False)):
                with self.subTest(iteration=i, disallowed=disallowed):
                    with self.assertRaises(PermissionError):
                        profile.add_signal(disallowed)
                    self.assertEqual(tuple(profile.signals), reference)
                    self.assertEqual(profile.prospect_id, "fixture-prospect")
                    self.assertEqual(profile.organization_name, "Fixture Organisation")
                    self.assertEqual(profile.confidence, 0.8)

    def test_late_denial_preserves_two_admitted_signals_and_order(self):
        profile, first = self.admitted()
        second = self.signal(confidence=0.6)
        profile.add_signal(second)
        before = tuple(profile.signals)
        denied = self.signal(interactive=True)
        with self.assertRaises(PermissionError):
            profile.add_signal(denied)
        self.assertEqual(tuple(profile.signals), before)
        self.assertIs(before[0], first)
        self.assertIs(before[1], second)
        self.assertAlmostEqual(profile.confidence, 0.7)


if __name__ == "__main__":
    unittest.main()
