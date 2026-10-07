from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class UnauthorizedDiscoveryProfileAdmissionBoundaryTest(unittest.TestCase):
    def signal(self, *, interactive=False):
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Public configuration signal",
            source="public-index",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=interactive,
        )

    def test_public_signals_view_is_an_exact_immutable_tuple(self):
        profile = ProspectProfile("prospect-1", "Example")

        self.assertIs(type(profile.signals), tuple)
        self.assertEqual(profile.signals, ())

    def test_valid_signal_is_admitted_only_through_add_signal(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()

        profile.add_signal(signal)

        self.assertIs(type(profile.signals), tuple)
        self.assertEqual(profile.signals, (signal,))

    def test_public_signals_view_cannot_bypass_admission_with_append(self):
        profile = ProspectProfile("prospect-1", "Example")
        rejected = self.signal(interactive=True)

        with self.assertRaises(AttributeError):
            profile.signals.append(rejected)

        self.assertEqual(profile.signals, ())

    def test_constructor_preseed_cannot_bypass_passive_discovery_validation(self):
        rejected = self.signal(interactive=True)

        try:
            profile = ProspectProfile(
                "prospect-1",
                "Example",
                signals=[rejected],
            )
        except (TypeError, ValueError, PermissionError):
            return

        self.fail(
            "constructor-supplied signals must not admit an unvalidated "
            f"interactive signal; got {profile.signals!r}"
        )


if __name__ == "__main__":
    unittest.main()
