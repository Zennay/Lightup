"""Source-bound, fictional ActivationGate policy-rebinding acceptance (#1476).

No scans, sockets, handlers, customer records or durable grants. A returned
ExecutionPermit is only an in-process object, never deployment authority.
The strict expected failures below are deliberately OPEN against current main.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


LAB = Target("127.0.0.1")
PUBLIC = Target(
    "review.example.test",
    authorization=Authorization(owner="fictional-owner", reference="FICTIONAL-REF-ONLY"),
)
CAPABILITY = "offline-inert-fixture"


def plan_gate() -> ActivationGate:
    return ActivationGate(ScopePolicy(), ActivationPolicy())


def explicit_public_gate() -> ActivationGate:
    return ActivationGate(
        ScopePolicy(explicit_hosts=frozenset({"review.example.test"})),
        ActivationPolicy(mode=ActivationMode.AUTHORIZED, activation_reference="FICTIONAL-SETUP"),
    )


class GateRebindingTests(unittest.TestCase):
    """All witnesses use the real installed source, with no network activity."""

    def test_normal_plan_only_stays_denied(self):
        gate = plan_gate()
        with self.assertRaisesRegex(PermissionError, "plan-only"):
            gate.issue(LAB, CAPABILITY)

    def test_valid_lab_configuration_control(self):
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="FICTIONAL-LAB"),
        )
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            permit = gate.issue(LAB, CAPABILITY)
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.target, "127.0.0.1")
        self.assertEqual(permit.capability_id, CAPABILITY)

    def test_policy_object_itself_rejects_field_mutation(self):
        p = ActivationPolicy()
        with self.assertRaises(FrozenInstanceError):
            p.mode = ActivationMode.AUTHORIZED

    def test_rebinding_witness_original_plan_only_object_no_longer_governs(self):
        gate = plan_gate()
        original = gate.activation_policy
        gate.activation_policy = ActivationPolicy(
            mode=ActivationMode.LAB_ONLY, activation_reference="FICTIONAL-LAB"
        )
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            permit = gate.issue(LAB, CAPABILITY)
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)
        self.assertIsNot(gate.activation_policy, original)
        self.assertIs(original.mode, ActivationMode.PLAN_ONLY)
        # A concrete successful witness protects the expected-RED from a
        # vacuous exception or a test that never reaches issue().
        self.assertEqual(permit.target, LAB.value)

    @unittest.expectedFailure
    def test_RED_plan_only_gate_must_not_be_promotable_after_initialization(self):
        gate = plan_gate()
        gate.activation_policy = ActivationPolicy(
            mode=ActivationMode.LAB_ONLY, activation_reference="FICTIONAL-LAB"
        )
        # EXPECTED SOURCE RED: today a permit is returned instead of refusal.
        with self.assertRaises(PermissionError):
            gate.issue(LAB, CAPABILITY)

    def test_constructor_rejects_missing_authorized_reference_control(self):
        with self.assertRaisesRegex(ValueError, "activation_reference"):
            ActivationGate(
                ScopePolicy(explicit_hosts=frozenset({"review.example.test"})),
                ActivationPolicy(mode=ActivationMode.AUTHORIZED),
            )

    def test_missing_reference_can_be_smuggled_via_rebinding_witness(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"review.example.test"})),
            ActivationPolicy(),
        )
        unauthorized_at_creation = gate.activation_policy
        gate.activation_policy = ActivationPolicy(mode=ActivationMode.AUTHORIZED)
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            permit = gate.issue(PUBLIC, CAPABILITY)
        self.assertIs(unauthorized_at_creation.mode, ActivationMode.PLAN_ONLY)
        self.assertIs(permit.mode, ActivationMode.AUTHORIZED)
        # The missing activation_reference is not revalidated by issue().
        self.assertIsNone(gate.activation_policy.activation_reference)
        self.assertEqual(permit.activation_reference, PUBLIC.authorization.reference)

    @unittest.expectedFailure
    def test_RED_swapping_invalid_authorized_policy_must_revalidate(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"review.example.test"})),
            ActivationPolicy(),
        )
        # EXPECTED SOURCE RED: assignment currently performs no validation.
        with self.assertRaises(ValueError):
            gate.activation_policy = ActivationPolicy(mode=ActivationMode.AUTHORIZED)

    def test_scope_only_swap_widens_existing_gate_witness(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset()),
            ActivationPolicy(mode=ActivationMode.AUTHORIZED, activation_reference="FICTIONAL-SETUP"),
        )
        decision = gate.scope_policy.decide(PUBLIC)
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)
        with self.assertRaises(PermissionError):
            gate.issue(PUBLIC, CAPABILITY)
        original = gate.scope_policy
        gate.scope_policy = ScopePolicy(explicit_hosts=frozenset({"review.example.test"}))
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            permit = gate.issue(PUBLIC, CAPABILITY)
        self.assertIsNot(gate.scope_policy, original)
        self.assertIs(permit.mode, ActivationMode.AUTHORIZED)
        self.assertEqual(permit.target, PUBLIC.value)

    @unittest.expectedFailure
    def test_RED_original_scope_must_remain_binding_after_scope_swap(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset()),
            ActivationPolicy(mode=ActivationMode.AUTHORIZED, activation_reference="FICTIONAL-SETUP"),
        )
        gate.scope_policy = ScopePolicy(explicit_hosts=frozenset({"review.example.test"}))
        # EXPECTED SOURCE RED: current gate accepts the widened replacement.
        with self.assertRaises(PermissionError):
            gate.issue(PUBLIC, CAPABILITY)

    def test_unchanged_explicit_public_gate_is_an_independent_control(self):
        gate = explicit_public_gate()
        permit = gate.issue(PUBLIC, CAPABILITY)
        self.assertIs(permit.mode, ActivationMode.AUTHORIZED)
        with self.assertRaises(PermissionError):
            gate.issue(Target("not-listed.example.test", PUBLIC.authorization), CAPABILITY)


if __name__ == "__main__":
    unittest.main()
