from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class UnauthorizedDiscoveryBooleanBoundaryTest(unittest.TestCase):
    def signal(self, **overrides):
        values = {
            "category": SignalCategory.CONFIGURATION,
            "summary": "Public configuration signal",
            "source": "public-index",
            "confidence": 0.8,
            "public_source": True,
            "requires_target_interaction": False,
        }
        values.update(overrides)
        return ProspectSignal(**values)

    def test_exact_public_non_interactive_signal_is_accepted(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()

        profile.add_signal(signal)

        self.assertEqual(profile.signals, [signal])

    def test_public_source_rejects_truthy_non_booleans(self):
        for value in (1, "false", object()):
            with self.subTest(value=value):
                signal = self.signal(public_source=value)
                with self.assertRaisesRegex(
                    ValueError,
                    "public_source must be an exact boolean",
                ):
                    signal.validate_for_unauthorized_discovery()

    def test_target_interaction_rejects_falsy_non_booleans(self):
        for value in (0, "", None):
            with self.subTest(value=value):
                signal = self.signal(requires_target_interaction=value)
                with self.assertRaisesRegex(
                    ValueError,
                    "requires_target_interaction must be an exact boolean",
                ):
                    signal.validate_for_unauthorized_discovery()

    def test_exact_private_source_remains_denied(self):
        with self.assertRaisesRegex(PermissionError, "requires a public source"):
            self.signal(public_source=False).validate_for_unauthorized_discovery()

    def test_exact_interactive_signal_remains_denied(self):
        with self.assertRaisesRegex(PermissionError, "cannot require target interaction"):
            self.signal(requires_target_interaction=True).validate_for_unauthorized_discovery()


if __name__ == "__main__":
    unittest.main()
