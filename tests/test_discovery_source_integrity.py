from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class _SourceText(str):
    pass


class UnauthorizedDiscoverySourceBoundaryTest(unittest.TestCase):
    def signal(self, source="public-index"):
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary="Public configuration signal",
            source=source,
            confidence=0.8,
            public_source=True,
            requires_target_interaction=False,
        )

    def test_exact_non_empty_source_text_is_accepted(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()

        profile.add_signal(signal)

        self.assertEqual(profile.signals, (signal,))

    def test_non_string_source_is_rejected_before_profile_mutation(self):
        for source in (None, 1, object()):
            with self.subTest(source=source):
                profile = ProspectProfile("prospect-1", "Example")
                signal = self.signal(source)

                with self.assertRaisesRegex(
                    ValueError,
                    "source must be exact non-empty text",
                ):
                    profile.add_signal(signal)

                self.assertIs(signal.source, source)
                self.assertEqual(profile.signals, ())

    def test_string_subclass_source_is_rejected_without_coercion(self):
        profile = ProspectProfile("prospect-1", "Example")
        source = _SourceText("public-index")
        signal = self.signal(source)

        with self.assertRaisesRegex(
            ValueError,
            "source must be exact non-empty text",
        ):
            profile.add_signal(signal)

        self.assertIs(signal.source, source)
        self.assertEqual(profile.signals, ())

    def test_blank_source_is_rejected_without_normalization(self):
        for source in ("", " ", "\t\n"):
            with self.subTest(source=repr(source)):
                profile = ProspectProfile("prospect-1", "Example")
                signal = self.signal(source)

                with self.assertRaisesRegex(
                    ValueError,
                    "source must be exact non-empty text",
                ):
                    profile.add_signal(signal)

                self.assertEqual(signal.source, source)
                self.assertEqual(profile.signals, ())


if __name__ == "__main__":
    unittest.main()
