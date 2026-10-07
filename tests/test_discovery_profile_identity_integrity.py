from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class UnauthorizedDiscoveryProfileIdentityBoundaryTest(unittest.TestCase):
    def signal(self):
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Public configuration signal",
            source="public-index",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=False,
        )

    def test_prospect_id_cannot_change_after_signal_admission(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()
        profile.add_signal(signal)

        with self.assertRaises((AttributeError, TypeError)):
            profile.prospect_id = "prospect-2"

        self.assertEqual(profile.prospect_id, "prospect-1")
        self.assertEqual(profile.signals, (signal,))

    def test_organization_name_cannot_change_after_signal_admission(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()
        profile.add_signal(signal)

        with self.assertRaises((AttributeError, TypeError)):
            profile.organization_name = "Different Org"

        self.assertEqual(profile.organization_name, "Example")
        self.assertEqual(profile.signals, (signal,))


if __name__ == "__main__":
    unittest.main()
