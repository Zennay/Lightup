import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import lightup.capabilities as capabilities
from lightup.capabilities import Capability, CapabilityState


class CapabilityMetadataValidationTests(unittest.TestCase):
    def test_canonical_capability_and_exported_registry_are_accepted(self):
        capability = Capability(
            "custom-review",
            "Custom review",
            "Bounded metadata-only review",
            CapabilityState.PLANNING,
        )

        self.assertEqual(capability.capability_id, "custom-review")
        self.assertIs(capability.state, CapabilityState.PLANNING)
        self.assertIs(capabilities.get_capabilities(), capabilities.REGISTRY)

    def test_non_canonical_capability_ids_fail_closed(self):
        invalid_ids = (
            "",
            " Web-Baseline",
            "web_baseline",
            "Web-Baseline",
            "-web-baseline",
            "web-baseline-",
            "web--baseline",
        )
        for capability_id in invalid_ids:
            with self.subTest(capability_id=capability_id):
                with self.assertRaisesRegex(ValueError, "canonical lowercase kebab-case"):
                    Capability(
                        capability_id,
                        "Name",
                        "Description",
                        CapabilityState.PLANNING,
                    )

    def test_blank_name_or_description_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "name must be a non-empty string"):
            Capability("valid-id", "   ", "Description", CapabilityState.PLANNING)
        with self.assertRaisesRegex(
            ValueError, "description must be a non-empty string"
        ):
            Capability("valid-id", "Name", "\t", CapabilityState.PLANNING)

    def test_string_state_lookalike_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "CapabilityState member"):
            Capability("valid-id", "Name", "Description", "planning")

    def test_truthy_non_boolean_activation_metadata_fails_closed(self):
        for value in (1, "true", object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "exact bool"):
                    Capability(
                        "valid-id",
                        "Name",
                        "Description",
                        CapabilityState.PLANNING,
                        requires_explicit_activation=value,
                    )

    def test_duplicate_registry_ids_fail_closed_on_export(self):
        first = Capability(
            "duplicate-id", "First", "First description", CapabilityState.PLANNING
        )
        second = Capability(
            "duplicate-id", "Second", "Second description", CapabilityState.LAB_ONLY
        )
        with patch.object(capabilities, "REGISTRY", (first, second)):
            with self.assertRaisesRegex(ValueError, "duplicate capability id"):
                capabilities.get_capabilities()

    def test_non_capability_registry_entry_fails_closed_on_export(self):
        with patch.object(capabilities, "REGISTRY", (object(),)):
            with self.assertRaisesRegex(ValueError, "only Capability records"):
                capabilities.get_capabilities()


if __name__ == "__main__":
    unittest.main()
