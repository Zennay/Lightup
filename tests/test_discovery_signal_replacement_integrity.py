from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class UnauthorizedDiscoverySignalReplacementBoundaryTest(unittest.TestCase):
    def signal(self, *, interactive=False):
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Public configuration signal",
            source="public-index",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=interactive,
        )

    def test_signal_collection_cannot_be_replaced_after_valid_admission(self):
        profile = ProspectProfile("prospect-1", "Example")
        admitted = self.signal()
        rejected = self.signal(interactive=True)
        replacement = [rejected]

        profile.add_signal(admitted)

        with self.assertRaises((AttributeError, TypeError)):
            profile.signals = replacement

        self.assertEqual(profile.signals, (admitted,))
        self.assertEqual(replacement, [rejected])

    def test_signal_collection_cannot_be_replaced_on_empty_profile(self):
        profile = ProspectProfile("prospect-1", "Example")
        rejected = self.signal(interactive=True)
        replacement = (rejected,)

        with self.assertRaises((AttributeError, TypeError)):
            profile.signals = replacement

        self.assertEqual(profile.signals, ())
        self.assertEqual(replacement, (rejected,))


if __name__ == "__main__":
    unittest.main()
