"""Issue #931: synthetic offline owner-source profile identity acceptance.

Strictly test-only, pinned to the unchanged PR #175 source head. An
expectedFailure is an OPEN AUTHORIZATION/PROVENANCE DEFECT, not approval.
No network, target, scan, credential, grant, or execution.
"""
from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory


class OpaqueIdentity:
    """Reject without calling coercion hooks on caller-controlled input."""

    def __init__(self):
        self.calls = 0

    def __str__(self):
        self.calls += 1
        raise AssertionError("identity must not be string-coerced")

    def __bool__(self):
        self.calls += 1
        raise AssertionError("identity must not be truth-tested")


class StringSubclass(str):
    def strip(self, *args, **kwargs):
        raise AssertionError("subclass strip must not be invoked")


def harmless_signal(**overrides):
    fields = dict(
        category=SignalCategory.CONFIGURATION,
        summary="fictional passive signal",
        source="synthetic-public-record",
        confidence=0.5,
        public_source=True,
        requires_target_interaction=False,
    )
    fields.update(overrides)
    return ProspectSignal(**fields)


class ProspectProfileIdentityOwnerContract(unittest.TestCase):
    """Tests of actual installed PR #175 source, not a mock policy."""

    def test_canonical_identity_preserved_without_normalizing(self):
        profile = ProspectProfile("Case-Sensitive-ID", "Example Organisation")
        self.assertIs(type(profile.prospect_id), str)
        self.assertIs(type(profile.organization_name), str)
        self.assertEqual(profile.prospect_id, "Case-Sensitive-ID")
        self.assertEqual(profile.organization_name, "Example Organisation")
        self.assertEqual(profile.signals, [])

    def test_canonical_identity_admits_only_passive_public_signal(self):
        profile = ProspectProfile("fictional-id", "Fictional Organisation")
        signal = harmless_signal()
        profile.add_signal(signal)
        self.assertEqual(profile.signals, [signal])
        self.assertEqual(profile.confidence, 0.5)

    def test_nonpublic_or_interactive_signals_cannot_enter_canonical_profile(self):
        profile = ProspectProfile("fictional-id", "Fictional Organisation")
        for signal in (
            harmless_signal(public_source=False),
            harmless_signal(requires_target_interaction=True),
            harmless_signal(public_source="true"),
        ):
            with self.subTest(signal=repr(signal)):
                with self.assertRaises((ValueError, PermissionError)):
                    profile.add_signal(signal)
                self.assertEqual(profile.signals, [])

    def test_valid_identity_does_not_replace_client_consent(self):
        """Passive profile identity by itself does not issue target authority."""
        profile = ProspectProfile("fictional-id", "Fictional Organisation")
        self.assertFalse(hasattr(profile, "authorization"))
        self.assertFalse(hasattr(profile, "permit"))
        self.assertEqual(profile.confidence, 0.0)

    @unittest.expectedFailure
    def test_red_null_prospect_id_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile(None, "Fictional Organisation")

    @unittest.expectedFailure
    def test_red_numeric_prospect_id_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile(1, "Fictional Organisation")

    @unittest.expectedFailure
    def test_red_subclass_prospect_id_must_fail_without_strip(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile(StringSubclass("fictional-id"), "Fictional Organisation")

    @unittest.expectedFailure
    def test_red_empty_prospect_id_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("", "Fictional Organisation")

    @unittest.expectedFailure
    def test_red_whitespace_prospect_id_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile(" \t\n", "Fictional Organisation")

    @unittest.expectedFailure
    def test_red_null_organization_name_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("fictional-id", None)

    @unittest.expectedFailure
    def test_red_numeric_organization_name_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("fictional-id", 0)

    @unittest.expectedFailure
    def test_red_subclass_organization_name_must_fail_without_strip(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("fictional-id", StringSubclass("Fictional Organisation"))

    @unittest.expectedFailure
    def test_red_empty_organization_name_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("fictional-id", "")

    @unittest.expectedFailure
    def test_red_whitespace_organization_name_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("fictional-id", " \t\n")

    @unittest.expectedFailure
    def test_red_polymorphic_identity_must_fail_without_coercion(self):
        poison = OpaqueIdentity()
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile(poison, "Fictional Organisation")
        self.assertEqual(poison.calls, 0)

    @unittest.expectedFailure
    def test_red_invalid_identity_must_fail_before_initial_signal_admission(self):
        signal = harmless_signal()
        with self.assertRaises((ValueError, TypeError)):
            ProspectProfile("", "Fictional Organisation", signals=[signal])

    def test_strict_oracle_detects_stale_expected_failure_labels(self):
        """Do not silently greenwash a fixed or unexpectedly skipped RED."""
        names = sorted(
            name for name in dir(type(self))
            if name.startswith("test_red_") and callable(getattr(type(self), name))
        )
        self.assertEqual(len(names), 12, "RED contract changed; owner must review")
        suite = unittest.TestSuite(type(self)(name) for name in names)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, len(names))
        self.assertEqual(len(result.expectedFailures), len(names))
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])


if __name__ == "__main__":
    unittest.main()
