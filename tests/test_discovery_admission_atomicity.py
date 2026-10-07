from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class PassiveDiscoveryAdmissionAtomicityTest(unittest.TestCase):
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

    def admitted_profile(self):
        profile = ProspectProfile("prospect-1", "Example Org")
        admitted = self.signal()
        profile.add_signal(admitted)
        return profile, admitted

    def assert_snapshot(self, profile, admitted):
        self.assertEqual(profile.prospect_id, "prospect-1")
        self.assertEqual(profile.organization_name, "Example Org")
        self.assertIs(type(profile.signals), tuple)
        self.assertEqual(profile.signals, (admitted,))
        self.assertEqual(profile.confidence, 0.8)

    def test_rejected_signal_variants_preserve_admitted_snapshot(self):
        cases = (
            ("raw category", self.signal(category="configuration"), ValueError),
            ("blank summary", self.signal(summary=" "), ValueError),
            ("blank source", self.signal(source=" "), ValueError),
            ("integer confidence", self.signal(confidence=1), ValueError),
            ("private source", self.signal(public_source=False), PermissionError),
            (
                "interactive source",
                self.signal(requires_target_interaction=True),
                PermissionError,
            ),
        )

        for name, rejected, error in cases:
            with self.subTest(case=name):
                profile, admitted = self.admitted_profile()

                with self.assertRaises(error):
                    profile.add_signal(rejected)

                self.assert_snapshot(profile, admitted)

    def test_public_collection_mutations_preserve_admitted_snapshot(self):
        profile, admitted = self.admitted_profile()
        rejected = self.signal(requires_target_interaction=True)
        replacement = (rejected,)

        with self.assertRaises(AttributeError):
            profile.signals.append(rejected)

        self.assert_snapshot(profile, admitted)

        with self.assertRaises((AttributeError, TypeError)):
            profile.signals = replacement

        self.assertEqual(replacement, (rejected,))
        self.assert_snapshot(profile, admitted)

    def test_identity_rebinding_preserves_admitted_snapshot(self):
        for field, replacement in (
            ("prospect_id", "prospect-2"),
            ("organization_name", "Different Org"),
        ):
            with self.subTest(field=field):
                profile, admitted = self.admitted_profile()

                with self.assertRaises((AttributeError, TypeError)):
                    setattr(profile, field, replacement)

                self.assert_snapshot(profile, admitted)


if __name__ == "__main__":
    unittest.main()
