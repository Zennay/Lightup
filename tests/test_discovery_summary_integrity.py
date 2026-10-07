from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class _SummaryText(str):
    pass


class UnauthorizedDiscoverySummaryBoundaryTest(unittest.TestCase):
    def signal(self, summary="Public configuration signal"):
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary=summary,
            source="public-index",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=False,
        )

    def test_canonical_summary_text_is_preserved(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()

        profile.add_signal(signal)

        self.assertEqual(signal.summary, "Public configuration signal")
        self.assertEqual(profile.signals, (signal,))

    def test_summary_rejects_non_exact_text_before_profile_mutation(self):
        for summary in (None, 1, object(), _SummaryText("signal")):
            with self.subTest(summary=summary):
                profile = ProspectProfile("prospect-1", "Example")
                signal = self.signal(summary)

                with self.assertRaisesRegex(
                    ValueError,
                    "summary must be exact non-empty text",
                ):
                    profile.add_signal(signal)

                self.assertIs(signal.summary, summary)
                self.assertEqual(profile.signals, ())

    def test_summary_rejects_blank_text_without_normalization(self):
        for summary in ("", " ", "\t\n"):
            with self.subTest(summary=repr(summary)):
                profile = ProspectProfile("prospect-1", "Example")
                signal = self.signal(summary)

                with self.assertRaisesRegex(
                    ValueError,
                    "summary must be exact non-empty text",
                ):
                    profile.add_signal(signal)

                self.assertEqual(signal.summary, summary)
                self.assertEqual(profile.signals, ())


if __name__ == "__main__":
    unittest.main()
