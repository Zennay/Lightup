import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class PassiveDiscoveryExactBooleanTests(unittest.TestCase):
    def _signal(self, **overrides):
        values = {
            "category": SignalCategory.CONFIGURATION,
            "summary": "public passive observation",
            "source": "public-index",
            "confidence": 0.8,
            "public_source": True,
            "requires_target_interaction": False,
        }
        values.update(overrides)
        return ProspectSignal(**values)

    def test_public_source_rejects_boolean_lookalikes(self):
        for value in ("false", 1, 0):
            with self.subTest(value=value):
                signal = self._signal(public_source=value)
                with self.assertRaisesRegex(
                    ValueError,
                    "public_source must be an exact bool",
                ):
                    signal.validate_for_unauthorized_discovery()

    def test_target_interaction_flag_rejects_boolean_lookalikes(self):
        for value in ("false", 1, 0, ""):
            with self.subTest(value=value):
                signal = self._signal(requires_target_interaction=value)
                with self.assertRaisesRegex(
                    ValueError,
                    "requires_target_interaction must be an exact bool",
                ):
                    signal.validate_for_unauthorized_discovery()

    def test_exact_false_public_source_keeps_existing_permission_denial(self):
        signal = self._signal(public_source=False)

        with self.assertRaisesRegex(
            PermissionError,
            "requires a public source",
        ):
            signal.validate_for_unauthorized_discovery()

    def test_exact_true_interaction_keeps_existing_permission_denial(self):
        signal = self._signal(requires_target_interaction=True)

        with self.assertRaisesRegex(
            PermissionError,
            "cannot require target interaction",
        ):
            signal.validate_for_unauthorized_discovery()

    def test_canonical_public_noninteractive_signal_remains_valid(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self._signal()

        profile.add_signal(signal)

        self.assertEqual(profile.signals, [signal])
        self.assertEqual(profile.confidence, 0.8)

    def test_type_confusion_fails_before_profile_mutation(self):
        profile = ProspectProfile("prospect-1", "Example")
        malformed = self._signal(requires_target_interaction=0)

        with self.assertRaisesRegex(
            ValueError,
            "requires_target_interaction must be an exact bool",
        ):
            profile.add_signal(malformed)

        self.assertEqual(profile.signals, [])


if __name__ == "__main__":
    unittest.main()
