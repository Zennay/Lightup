"""Offline installed-source acceptance for issue #1487 (not a release gate).

A minted ExecutionPermit is a *data object*, never dispatched, persisted,
or sent to any target by this suite. Expected failures are real unresolved
source contracts, not assertions of a vulnerability in deployed adapters.
"""
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class InertString(str):
    """Annotation-compatible subclass that must not become audit authority."""


class LabReferenceProvenance1487(unittest.TestCase):
    def setUp(self):
        # Prove that the *actual* source gate can be tested without ever
        # invoking sockets, name resolution, processes, or a live adapter.
        self._guards = [
            patch.object(socket, "socket", side_effect=AssertionError("network disabled")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS disabled")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process disabled")),
            patch.object(os, "system", side_effect=AssertionError("shell disabled")),
        ]
        for guard in self._guards:
            guard.start()
            self.addCleanup(guard.stop)

    def _gate(self, reference):
        return ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference=reference),
        )

    def _permit(self, reference):
        return self._gate(reference).issue(Target("127.0.0.1"), "fictional-review-only")

    def test_explicit_lab_reference_stays_bound_to_actual_permit(self):
        permit = self._permit("LAB-SYNTHETIC-SESSION-001")
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.target, "127.0.0.1")
        self.assertEqual(permit.capability_id, "fictional-review-only")
        self.assertEqual(permit.activation_reference, "LAB-SYNTHETIC-SESSION-001")
        self.assertTrue(permit.permit_id)

    def test_explicit_lab_reference_is_not_a_public_scope_override(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"public.example.test"})),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-001"),
        )
        target = Target(
            "public.example.test",
            authorization=Authorization(owner="fictional", reference="CONSENT-FICTIONAL"),
        )
        with self.assertRaises(PermissionError):
            gate.issue(target, "fictional-review-only")

    def test_plan_only_blocks_inert_loopback_regardless_of_reference(self):
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.PLAN_ONLY, activation_reference="LAB-001"),
        )
        with self.assertRaises(PermissionError):
            gate.issue(Target("127.0.0.1"), "fictional-review-only")

    def test_source_witness_missing_reference_currently_stamps_generic_lab(self):
        # Ordinary green witness must remain separate from future expected RED.
        permit = self._permit(None)
        self.assertEqual(permit.activation_reference, "LAB")

    def test_source_witness_empty_reference_currently_stamps_generic_lab(self):
        permit = self._permit("")
        self.assertEqual(permit.activation_reference, "LAB")

    def test_source_witness_whitespace_reference_is_not_normalized(self):
        permit = self._permit(" \t ")
        self.assertEqual(permit.activation_reference, " \t ")

    def test_source_witness_truthy_nonstring_reference_is_retained(self):
        permit = self._permit(7)
        self.assertIs(type(permit.activation_reference), int)
        self.assertEqual(permit.activation_reference, 7)

    def test_source_witness_string_subclass_reference_is_retained(self):
        special = InertString("LAB-SUBCLASS")
        permit = self._permit(special)
        self.assertIs(permit.activation_reference, special)

    @unittest.expectedFailure
    def test_source_red_missing_lab_reference_must_fail_at_construction(self):
        with self.assertRaises(ValueError):
            self._gate(None)

    @unittest.expectedFailure
    def test_source_red_blank_lab_reference_must_fail_at_construction(self):
        with self.assertRaises(ValueError):
            self._gate(" \t ")

    @unittest.expectedFailure
    def test_source_red_nonstring_lab_reference_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            self._gate(7)

    @unittest.expectedFailure
    def test_source_red_subclass_lab_reference_must_fail_at_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            self._gate(InertString("LAB-SUBCLASS"))


if __name__ == "__main__":
    unittest.main()
