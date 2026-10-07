from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class ConfidenceSubclass(float):
    pass


def _signal(confidence: object) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.CONFIGURATION,
        summary="Public passive configuration signal.",
        source="public-dataset",
        confidence=confidence,  # type: ignore[arg-type]
        public_source=True,
        requires_target_interaction=False,
    )


class PassiveDiscoveryConfidenceTypeTests(unittest.TestCase):
    def test_exact_builtin_float_confidence_controls_remain_valid(self) -> None:
        for confidence in (0.0, 0.7, 1.0):
            with self.subTest(confidence=confidence):
                profile = ProspectProfile("p-confidence", "Example")
                signal = _signal(confidence)

                profile.add_signal(signal)

                self.assertEqual(profile.signals, (signal,))
                self.assertIs(type(profile.signals[0].confidence), float)

    def test_exact_out_of_range_float_remains_rejected(self) -> None:
        for confidence in (-0.01, 1.01):
            with self.subTest(confidence=confidence):
                profile = ProspectProfile("p-confidence", "Example")

                with self.assertRaisesRegex(
                    ValueError,
                    "confidence must be between 0 and 1",
                ):
                    profile.add_signal(_signal(confidence))

                self.assertEqual(profile.signals, ())

    def test_noncanonical_numeric_confidence_fails_before_admission(self) -> None:
        invalid_values = (
            False,
            True,
            0,
            1,
            ConfidenceSubclass(0.7),
        )
        for confidence in invalid_values:
            with self.subTest(confidence=repr(confidence)):
                profile = ProspectProfile("p-confidence", "Example")
                signal = _signal(confidence)

                with self.assertRaisesRegex(
                    ValueError,
                    "confidence.*exact.*float|exact.*float.*confidence",
                ):
                    profile.add_signal(signal)

                self.assertEqual(profile.signals, ())


if __name__ == "__main__":
    unittest.main()
