"""#925: passive profile constructor/collection admission bypass owner REDs.

Isolated in-memory acceptance pinned to PR #175 source head
df9eac879bbe232cd1e50fd6e9dfe12ff38f8469. No discovery IO.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import (
    ProspectProfile,
    ProspectSignal,
    SignalCategory,
)


def signal(
    *,
    public_source: bool = True,
    requires_target_interaction: bool = False,
    confidence: float = 0.75,
) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.ASSET,
        summary="Fictional asset metadata; not a target",
        source="https://docs.example.test/",
        confidence=confidence,
        public_source=public_source,
        requires_target_interaction=requires_target_interaction,
    )


def empty_profile() -> ProspectProfile:
    return ProspectProfile(
        prospect_id="fictional-925",
        organization_name="Fictional Only",
    )


class ExistingAdmissionControls925(unittest.TestCase):
    def test_canonical_add_admits_public_noninteractive(self) -> None:
        p = empty_profile()
        candidate = signal()
        p.add_signal(candidate)
        self.assertEqual(tuple(p.signals), (candidate,))

    def test_rejected_nonpublic_signal_is_atomic(self) -> None:
        p = empty_profile()
        good = signal()
        p.add_signal(good)
        before = tuple(p.signals)
        with self.assertRaises(PermissionError):
            p.add_signal(signal(public_source=False))
        self.assertEqual(tuple(p.signals), before)
        self.assertIs(tuple(p.signals)[0], good)

    def test_rejected_interactive_signal_is_atomic(self) -> None:
        p = empty_profile()
        good = signal()
        p.add_signal(good)
        before = tuple(p.signals)
        with self.assertRaises(PermissionError):
            p.add_signal(signal(requires_target_interaction=True))
        self.assertEqual(tuple(p.signals), before)

    def test_invalid_confidence_rejected_without_insertion(self) -> None:
        p = empty_profile()
        with self.assertRaises(ValueError):
            p.add_signal(signal(confidence=3.0))
        self.assertEqual(tuple(p.signals), ())

    def test_rejected_candidate_is_never_repaired_or_coerced(self) -> None:
        p = empty_profile()
        candidate = signal(public_source=False, requires_target_interaction=True)
        with self.assertRaises(PermissionError):
            p.add_signal(candidate)
        self.assertIs(candidate.public_source, False)
        self.assertIs(candidate.requires_target_interaction, True)
        self.assertEqual(tuple(p.signals), ())


class BypassSourceOwnerRED925(unittest.TestCase):
    """Expected failures: do not mistake successful CI for repaired admission."""

    @unittest.expectedFailure
    def test_constructor_must_not_preseed_nonpublic_signal(self) -> None:
        with self.assertRaises((ValueError, PermissionError)):
            ProspectProfile(
                prospect_id="fake",
                organization_name="Fictional",
                signals=[signal(public_source=False)],
            )

    @unittest.expectedFailure
    def test_constructor_must_not_preseed_interactive_signal(self) -> None:
        with self.assertRaises((ValueError, PermissionError)):
            ProspectProfile(
                prospect_id="fake",
                organization_name="Fictional",
                signals=[signal(requires_target_interaction=True)],
            )

    @unittest.expectedFailure
    def test_constructor_must_not_preseed_malformed_confidence(self) -> None:
        with self.assertRaises((ValueError, PermissionError)):
            ProspectProfile(
                prospect_id="fake",
                organization_name="Fictional",
                signals=[signal(confidence=3.0)],
            )

    @unittest.expectedFailure
    def test_public_signals_view_must_not_be_mutable(self) -> None:
        p = empty_profile()
        with self.assertRaises((AttributeError, TypeError)):
            p.signals.append(signal(public_source=False))

    @unittest.expectedFailure
    def test_direct_collection_rebinding_must_not_bypass_admission(self) -> None:
        p = empty_profile()
        with self.assertRaises((AttributeError, TypeError)):
            p.signals = [signal(requires_target_interaction=True)]

    @unittest.expectedFailure
    def test_mutating_constructor_list_cannot_insert_after_creation(self) -> None:
        initial = [signal()]
        p = ProspectProfile(
            prospect_id="fake",
            organization_name="Fictional",
            signals=initial,
        )
        original = tuple(p.signals)
        initial.append(signal(public_source=False))
        self.assertEqual(tuple(p.signals), original)
        self.assertIs(tuple(p.signals)[0], initial[0])


if __name__ == "__main__":
    unittest.main()
