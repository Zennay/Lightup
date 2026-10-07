from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


def _canonical_signal(
    *,
    public_source: bool = True,
    requires_target_interaction: bool = False,
) -> ProspectSignal:
    return ProspectSignal(
        category=SignalCategory.CONFIGURATION,
        summary="Public passive configuration signal.",
        source="public-dataset",
        confidence=0.7,
        public_source=public_source,
        requires_target_interaction=requires_target_interaction,
    )


class BypassSignal(ProspectSignal):
    def validate_for_unauthorized_discovery(self) -> None:
        return None


class DuckSignal:
    category = SignalCategory.CONFIGURATION
    summary = "Forged passive signal"
    source = "private-interactive-source"
    confidence = 1.0
    public_source = False
    requires_target_interaction = True

    def validate_for_unauthorized_discovery(self) -> None:
        return None


class PassiveDiscoverySignalObjectTests(unittest.TestCase):
    def test_exact_canonical_signal_remains_admissible(self) -> None:
        profile = ProspectProfile("p-signal", "Example")
        signal = _canonical_signal()

        profile.add_signal(signal)

        self.assertEqual(profile.signals, (signal,))
        self.assertIs(type(profile.signals[0]), ProspectSignal)

    def test_exact_interactive_signal_remains_denied(self) -> None:
        profile = ProspectProfile("p-signal", "Example")

        with self.assertRaises(PermissionError):
            profile.add_signal(
                _canonical_signal(requires_target_interaction=True)
            )

        self.assertEqual(profile.signals, ())

    def test_exact_nonpublic_signal_remains_denied(self) -> None:
        profile = ProspectProfile("p-signal", "Example")

        with self.assertRaises(PermissionError):
            profile.add_signal(_canonical_signal(public_source=False))

        self.assertEqual(profile.signals, ())

    def test_signal_subclass_cannot_replace_authorization_validator(self) -> None:
        profile = ProspectProfile("p-signal", "Example")
        signal = BypassSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Interactive private signal.",
            source="private-source",
            confidence=0.7,
            public_source=False,
            requires_target_interaction=True,
        )

        with self.assertRaisesRegex(
            ValueError,
            "signal.*exact.*ProspectSignal|exact.*ProspectSignal.*signal",
        ):
            profile.add_signal(signal)

        self.assertEqual(profile.signals, ())

    def test_duck_signal_cannot_supply_custom_authorization_validator(self) -> None:
        profile = ProspectProfile("p-signal", "Example")

        with self.assertRaisesRegex(
            ValueError,
            "signal.*exact.*ProspectSignal|exact.*ProspectSignal.*signal",
        ):
            profile.add_signal(DuckSignal())  # type: ignore[arg-type]

        self.assertEqual(profile.signals, ())


if __name__ == "__main__":
    unittest.main()
