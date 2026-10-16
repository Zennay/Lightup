"""#1511 read-only compatibility canary against the actual SOURCE registry.

The high-level capability registry describes product features, not operator
consent or active scan authorization. Compatibility is NEVER release proof.
"""
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.fictional_lab_capability_review_1511 import (
    _canonical_capability_id,
    review_fictional_lab_capability_1511 as single,
)
from lightup.fictional_lab_capability_batch_1511 import (
    review_fictional_lab_capability_cohort_1511 as batch,
)


class FictionalLabCapabilityRegistryCompatibility1511Tests(unittest.TestCase):
    def test_all_source_registry_ids_fit_canonical_identity_schema(self):
        catalog = get_capabilities()
        self.assertIs(type(catalog), tuple)
        self.assertEqual(len(catalog), 31)
        ids = []
        for entry in catalog:
            self.assertIs(type(entry), Capability)
            self.assertIs(type(entry.capability_id), str)
            self.assertTrue(_canonical_capability_id(entry.capability_id), entry.capability_id)
            self.assertIs(entry.requires_explicit_activation, True)
            ids.append(entry.capability_id)
        self.assertEqual(len(set(ids)), len(ids))

    def test_only_five_current_source_capabilities_are_labelled_lab_only(self):
        catalog = get_capabilities()
        actual_lab = {entry.capability_id for entry in catalog if entry.state is CapabilityState.LAB_ONLY}
        self.assertEqual(actual_lab, {
            "ot-lab", "wireless-lab", "social-engineering-lab",
            "human-layer-lab", "physical-security-lab",
        })
        self.assertEqual(sum(e.state is CapabilityState.PLANNING for e in catalog), 26)
        self.assertFalse(any(e.state is CapabilityState.DISABLED for e in catalog))

    def test_catalog_id_review_never_authenticates_any_capability(self):
        for entry in get_capabilities():
            with self.subTest(identity=entry.capability_id):
                response = single(entry.capability_id, (entry.capability_id,))
                self.assertEqual(response.status, "REVIEW_ONLY")
                self.assertFalse(response.authorized)
                self.assertFalse(response.consent_verified)
                self.assertFalse(response.dispatch_allowed)
                self.assertFalse(response.release_allowed)

    def test_full_copied_source_catalog_is_only_an_untrusted_fictional_batch(self):
        ids = tuple(entry.capability_id for entry in get_capabilities())
        response = batch(ids, ids)
        self.assertEqual(response.status, "REVIEW_ONLY")
        self.assertFalse(response.authorized)
        self.assertFalse(response.consent_verified)
        self.assertFalse(response.dispatch_allowed)
        self.assertFalse(response.release_allowed)

    def test_copying_planning_ids_never_licenses_lab_active_execution(self):
        planned = tuple(entry.capability_id for entry in get_capabilities()
                        if entry.state is CapabilityState.PLANNING)
        self.assertEqual(len(planned), 26)
        response = batch(planned, planned)
        self.assertEqual(response.status, "REVIEW_ONLY")
        self.assertIs(response.authorized, False)
        self.assertIs(response.consent_verified, False)
        self.assertIs(response.dispatch_allowed, False)
        self.assertIs(response.release_allowed, False)

    def test_copying_lab_only_ids_never_proves_actual_approval(self):
        lab = tuple(entry.capability_id for entry in get_capabilities()
                    if entry.state is CapabilityState.LAB_ONLY)
        response = batch(lab, lab)
        self.assertEqual(response.status, "REVIEW_ONLY")
        self.assertIs(response.authorized, False)
        self.assertIs(response.consent_verified, False)
        self.assertIs(response.dispatch_allowed, False)
        self.assertIs(response.release_allowed, False)

    def test_synthetic_missing_or_fabricated_catalog_id_atomic_hold(self):
        real = tuple(entry.capability_id for entry in get_capabilities())
        for index in (0, 10, 25, len(real) - 1):
            altered = real[:index] + ("fabricated-lab-tool",) + real[index + 1:]
            result = batch(altered, real)
            self.assertEqual(result.status, "HOLD")
            self.assertFalse(result.dispatch_allowed)

    def test_readonly_source_registry_review_without_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            real = tuple(entry.capability_id for entry in get_capabilities())
            response = batch(real, real)
            self.assertEqual(response.status, "REVIEW_ONLY")
            self.assertFalse(response.authorized)


if __name__ == "__main__":
    unittest.main()
