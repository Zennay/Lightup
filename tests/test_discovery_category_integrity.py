from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class _SignalCategoryText(str):
    pass


class UnauthorizedDiscoveryCategoryBoundaryTest(unittest.TestCase):
    def signal(self, category=SignalCategory.CONFIGURATION):
        return ProspectSignal(
            category=category,
            summary="Public configuration signal",
            source="public-index",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=False,
        )

    def test_exact_signal_category_is_accepted(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal()

        profile.add_signal(signal)

        self.assertEqual(profile.signals, [signal])

    def test_raw_string_category_is_rejected_before_profile_mutation(self):
        profile = ProspectProfile("prospect-1", "Example")
        signal = self.signal("configuration")

        with self.assertRaisesRegex(
            ValueError,
            "category must be an exact SignalCategory",
        ):
            profile.add_signal(signal)

        self.assertEqual(profile.signals, [])

    def test_string_subclass_category_is_rejected_without_coercion(self):
        profile = ProspectProfile("prospect-1", "Example")
        category = _SignalCategoryText("configuration")
        signal = self.signal(category)

        with self.assertRaisesRegex(
            ValueError,
            "category must be an exact SignalCategory",
        ):
            profile.add_signal(signal)

        self.assertIs(signal.category, category)
        self.assertEqual(profile.signals, [])

    def test_unrelated_category_object_is_rejected_before_profile_mutation(self):
        profile = ProspectProfile("prospect-1", "Example")
        category = object()
        signal = self.signal(category)

        with self.assertRaisesRegex(
            ValueError,
            "category must be an exact SignalCategory",
        ):
            profile.add_signal(signal)

        self.assertIs(signal.category, category)
        self.assertEqual(profile.signals, [])


if __name__ == "__main__":
    unittest.main()
