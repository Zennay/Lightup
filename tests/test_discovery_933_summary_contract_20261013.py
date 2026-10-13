from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class PassiveSummaryAdmissionContract(unittest.TestCase):
    """Issue #933: expected-RED until PR #175 source owner absorbs the fix."""

    def signal(self, summary: object) -> ProspectSignal:
        return ProspectSignal(
            category=SignalCategory.CONFIGURATION,
            summary=summary,
            source="public-index",
            confidence=0.75,
            public_source=True,
            requires_target_interaction=False,
        )

    def test_exact_str_keeps_original_text_and_signal_identity(self) -> None:
        summary = "  Public observation — no target interaction  "
        signal = self.signal(summary)
        profile = ProspectProfile("prospect-1", "Example")
        profile.add_signal(signal)
        self.assertEqual(len(profile.signals), 1)
        self.assertIs(profile.signals[0], signal)
        self.assertEqual(signal.summary, summary)

    @unittest.expectedFailure
    def test_none_summary_must_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            self.signal(None).validate_for_unauthorized_discovery()

    @unittest.expectedFailure
    def test_arbitrary_object_summary_must_not_be_coerced(self) -> None:
        class ExplosiveString:
            def __str__(self) -> str:
                raise AssertionError("caller data must not be coerced")

        with self.assertRaises(ValueError):
            self.signal(ExplosiveString()).validate_for_unauthorized_discovery()

    @unittest.expectedFailure
    def test_string_subclass_must_not_pass_as_canonical_text(self) -> None:
        class PolymorphicSummary(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("subclass methods must not be invoked")

        with self.assertRaises(ValueError):
            self.signal(PolymorphicSummary("public signal")).validate_for_unauthorized_discovery()

    @unittest.expectedFailure
    def test_unicode_whitespace_only_summary_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.signal("\u2003\u00a0\t\n").validate_for_unauthorized_discovery()

    @unittest.expectedFailure
    def test_failed_summary_admission_preserves_existing_profile(self) -> None:
        first = self.signal("Previously admitted public observation")
        profile = ProspectProfile("prospect-1", "Example")
        profile.add_signal(first)
        prior = profile.signals
        invalid = self.signal(None)
        with self.assertRaises(ValueError):
            profile.add_signal(invalid)
        self.assertIs(profile.signals, prior)
        self.assertEqual(profile.signals, [first])
        self.assertIs(profile.signals[0], first)
        self.assertIsNone(invalid.summary)

    def test_existing_passive_boundary_still_denies_interaction(self) -> None:
        signal = self.signal("Public observation")
        object.__setattr__(signal, "requires_target_interaction", True)
        profile = ProspectProfile("prospect-1", "Example")
        with self.assertRaises(PermissionError):
            profile.add_signal(signal)
        self.assertEqual(profile.signals, [])


if __name__ == "__main__":
    unittest.main()
