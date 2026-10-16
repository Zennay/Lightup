"""Offline tests of the unwired, non-authorizing lifetime reviewer (#1476)."""
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
import lightup.activation_gate_lifetime_review_1476 as review_module
from lightup.scope import ScopePolicy
from lightup.activation_gate_lifetime_review_1476 import (
    LifetimeStatus,
    LifetimeReceipt,
    PinnedGateReview,
    pin_gate_for_offline_review,
    review_gate_lifetime,
)


def gate(
    scope: ScopePolicy | None = None,
    activation: ActivationPolicy | None = None,
) -> ActivationGate:
    return ActivationGate(
        scope if scope is not None else ScopePolicy(),
        activation if activation is not None else ActivationPolicy(),
    )


class LifetimeReviewTests(unittest.TestCase):
    def check_no_authority(self, receipt):
        self.assertIn(receipt.status, (LifetimeStatus.HOLD, LifetimeStatus.REVIEW_ONLY))
        for attr in (
            "may_issue_permit", "may_issue_grant", "may_dispatch",
            "may_scan", "may_deploy", "may_release",
        ):
            self.assertIs(getattr(receipt, attr), False)

    def test_unchanged_plan_is_only_review_not_permission(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        self.assertIsNotNone(pin)
        receipt = review_gate_lifetime(g, pin)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(receipt.reason, "unchanged")
        self.check_no_authority(receipt)

    def test_unchanged_valid_lab_is_still_non_authorizing(self):
        g = gate(activation=ActivationPolicy(mode=ActivationMode.LAB_ONLY))
        result = review_gate_lifetime(g, pin_gate_for_offline_review(g))
        self.assertIs(result.status, LifetimeStatus.REVIEW_ONLY)
        self.check_no_authority(result)

    def test_unchanged_authorized_policy_is_still_non_authorizing(self):
        g = gate(
            scope=ScopePolicy(explicit_hosts=frozenset({"fictional.example.test"})),
            activation=ActivationPolicy(ActivationMode.AUTHORIZED, "FAKE-REF"),
        )
        receipt = review_gate_lifetime(g, pin_gate_for_offline_review(g))
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.check_no_authority(receipt)

    def test_plan_to_lab_swap_is_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY, "FAKE-LAB")
        receipt = review_gate_lifetime(g, pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assertEqual(receipt.reason, "changed")
        self.check_no_authority(receipt)

    def test_swap_to_invalid_authorized_mode_is_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        g.activation_policy = ActivationPolicy(ActivationMode.AUTHORIZED)
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_replace_scope_with_broader_allowlist_is_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        g.scope_policy = ScopePolicy(explicit_hosts=frozenset({"fictional.example.test"}))
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_equivalent_policy_replacement_is_also_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        g.activation_policy = ActivationPolicy()
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_equivalent_scope_replacement_is_also_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        g.scope_policy = ScopePolicy()
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_internal_policy_field_bypass_is_detected(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        object.__setattr__(g.activation_policy, "mode", ActivationMode.LAB_ONLY)
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_internal_scope_field_bypass_is_detected(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        object.__setattr__(
            g.scope_policy, "explicit_hosts",
            frozenset({"fictional.example.test"}),
        )
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_new_mutable_alias_on_same_scope_object_is_detected(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        external = ["fictional.example.test"]
        object.__setattr__(g.scope_policy, "explicit_networks", external)
        self.assertIs(review_gate_lifetime(g, pin).status, LifetimeStatus.HOLD)

    def test_altered_boolean_type_is_not_accepted(self):
        invalid = ScopePolicy(allow_private_lab=1)
        g = gate(scope=invalid)
        self.assertIsNone(pin_gate_for_offline_review(g))
        original = gate()
        pin = pin_gate_for_offline_review(original)
        object.__setattr__(original.scope_policy, "allow_private_lab", 1)
        self.assertIs(review_gate_lifetime(original, pin).status, LifetimeStatus.HOLD)

    def test_noncanonical_collections_rejected_before_pin(self):
        for scope in (
            ScopePolicy(explicit_hosts={"fictional.example.test"}),
            ScopePolicy(explicit_networks=["192.0.2.0/24"]),
            ScopePolicy(explicit_hosts=frozenset({1})),
            ScopePolicy(explicit_networks=(None,)),
        ):
            with self.subTest(scope=type(scope.explicit_hosts).__name__):
                self.assertIsNone(pin_gate_for_offline_review(gate(scope=scope)))

    def test_fake_string_subclasses_not_canonical(self):
        class DisplayStr(str):
            pass
        scopes = (
            ScopePolicy(explicit_hosts=frozenset({DisplayStr("a.example.test")})),
            ScopePolicy(explicit_networks=(DisplayStr("192.0.2.0/24"),)),
        )
        for scope in scopes:
            self.assertIsNone(pin_gate_for_offline_review(gate(scope=scope)))
        self.assertIsNone(
            pin_gate_for_offline_review(gate(
                activation=ActivationPolicy(
                    ActivationMode.AUTHORIZED, DisplayStr("FAKE-REF"))
            ))
        )

    def test_unknown_activation_mode_does_not_pin(self):
        g = gate(activation=ActivationPolicy(mode="plan_only"))
        self.assertIsNone(pin_gate_for_offline_review(g))

    def test_missing_or_invalid_references_not_pinned(self):
        for reference in (None, "", "x" * 2049, 7):
            with self.subTest(size=type(reference).__name__):
                invalid = ActivationPolicy(ActivationMode.AUTHORIZED, reference)
                # Direct source constructor rejects missing AUTHORIZED refs,
                # so the source instance is created safely and then swapped.
                g = gate()
                g.activation_policy = invalid
                self.assertIsNone(pin_gate_for_offline_review(g))

    def test_bounded_collections(self):
        hosts = frozenset(f"h{i}.example.test" for i in range(256))
        self.assertIsNotNone(pin_gate_for_offline_review(gate(
            scope=ScopePolicy(explicit_hosts=hosts)
        )))
        bigger = frozenset(f"h{i}.example.test" for i in range(257))
        self.assertIsNone(pin_gate_for_offline_review(gate(
            scope=ScopePolicy(explicit_hosts=bigger)
        )))
        self.assertIsNone(pin_gate_for_offline_review(gate(
            scope=ScopePolicy(explicit_networks=("z" * 2049,))
        )))

    def test_wrong_gate_or_snapshot_object_hold_not_crash(self):
        g1, g2 = gate(), gate()
        pin = pin_gate_for_offline_review(g1)
        for value, pinned in ((g2, pin), (g1, object()), (object(), pin), (g1, None)):
            receipt = review_gate_lifetime(value, pinned)
            self.assertIs(receipt.status, LifetimeStatus.HOLD)
            self.check_no_authority(receipt)

    def test_subclass_objects_are_rejected(self):
        class EvilGate(ActivationGate):
            pass
        class EvilScope(ScopePolicy):
            pass
        self.assertIsNone(pin_gate_for_offline_review(EvilGate(ScopePolicy(), ActivationPolicy())))
        self.assertIsNone(pin_gate_for_offline_review(gate(scope=EvilScope())))

    def test_never_calls_original_issue_or_external_effects(self):
        g = gate()
        with patch.object(ActivationGate, "issue", side_effect=AssertionError("permit forbidden")), \
             patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            pin = pin_gate_for_offline_review(g)
            receipt = review_gate_lifetime(g, pin)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.check_no_authority(receipt)

    def test_uninitialized_gate_is_not_pinned(self):
        uninitialized = object.__new__(ActivationGate)
        self.assertIsNone(pin_gate_for_offline_review(uninitialized))
        self.assertIs(
            review_gate_lifetime(uninitialized, object()).status,
            LifetimeStatus.HOLD,
        )

    def test_deleted_gate_policy_field_is_generic_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        del g.activation_policy
        receipt = review_gate_lifetime(g, pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.check_no_authority(receipt)
        self.assertIsNone(pin_gate_for_offline_review(g))

    def test_deleted_nested_fields_hold_without_exception(self):
        for deleted_field in ("explicit_hosts", "allow_private_lab"):
            with self.subTest(deleted_field=deleted_field):
                g = gate()
                pin = pin_gate_for_offline_review(g)
                object.__delattr__(g.scope_policy, deleted_field)
                receipt = review_gate_lifetime(g, pin)
                self.assertIs(receipt.status, LifetimeStatus.HOLD)
                self.check_no_authority(receipt)
                self.assertIsNone(pin_gate_for_offline_review(g))

    def test_deleted_activation_dataclass_field_cannot_fall_back_to_default(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        object.__delattr__(g.activation_policy, "mode")
        result = review_gate_lifetime(g, pin)
        self.assertIs(result.status, LifetimeStatus.HOLD)
        self.check_no_authority(result)
        self.assertIsNone(pin_gate_for_offline_review(g))

    def test_injected_unknown_policy_metadata_must_hold(self):
        for obj_name in ("scope_policy", "activation_policy"):
            with self.subTest(obj_name=obj_name):
                g = gate()
                pin = pin_gate_for_offline_review(g)
                vars(getattr(g, obj_name))["unexpected_control"] = "fictional"
                result = review_gate_lifetime(g, pin)
                self.assertIs(result.status, LifetimeStatus.HOLD)
                self.check_no_authority(result)
                self.assertIsNone(pin_gate_for_offline_review(g))

    def test_injected_gate_metadata_must_hold(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        vars(g)["unexpected_runtime_flag"] = True
        result = review_gate_lifetime(g, pin)
        self.assertIs(result.status, LifetimeStatus.HOLD)
        self.check_no_authority(result)
        self.assertIsNone(pin_gate_for_offline_review(g))

    def test_uninitialized_snapshot_returns_generic_hold_instead_of_exception(self):
        g = gate()
        incomplete = object.__new__(PinnedGateReview)
        receipt = review_gate_lifetime(g, incomplete)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assertEqual(receipt.reason, "changed")
        self.check_no_authority(receipt)

    def test_partial_snapshot_fields_do_not_leak_attribute_error(self):
        g = gate()
        incomplete = object.__new__(PinnedGateReview)
        object.__setattr__(incomplete, "gate", g)
        receipt = review_gate_lifetime(g, incomplete)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.check_no_authority(receipt)

    def test_pin_rechecks_scope_mutated_during_activation_snapshot(self):
        g = gate()
        original = review_module._activation_fields
        calls = [0]

        def mutate_during_activation_check(policy):
            fields = original(policy)
            calls[0] += 1
            if calls[0] == 1:
                object.__setattr__(
                    g.scope_policy, "explicit_hosts",
                    frozenset({"fictional.example.test"}),
                )
            return fields

        with patch.object(review_module, "_activation_fields",
                          side_effect=mutate_during_activation_check):
            # First snapshot has the OLD scope, then activation evaluation
            # changes the real original scope. Old pin() accepted a stale pin.
            pin = pin_gate_for_offline_review(g)
        self.assertIsNone(pin)
        self.assertGreaterEqual(calls[0], 2)

    def test_pin_detects_gate_rebinding_during_field_snapshot(self):
        g = gate()
        original = review_module._activation_fields
        calls = [0]

        def rebind_during_snapshot(policy):
            fields = original(policy)
            calls[0] += 1
            if calls[0] == 1:
                g.activation_policy = ActivationPolicy()
            return fields

        with patch.object(review_module, "_activation_fields",
                          side_effect=rebind_during_snapshot):
            self.assertIsNone(pin_gate_for_offline_review(g))
        self.assertGreaterEqual(calls[0], 1)

    def test_review_second_pass_detects_scope_change_inside_activation_read(self):
        g = gate()
        pin = pin_gate_for_offline_review(g)
        original = review_module._activation_fields
        calls = [0]

        def mutate_during_review(policy):
            fields = original(policy)
            calls[0] += 1
            if calls[0] == 1:
                object.__setattr__(
                    g.scope_policy, "explicit_hosts",
                    frozenset({"fictional.example.test"}),
                )
            return fields

        with patch.object(review_module, "_activation_fields",
                          side_effect=mutate_during_review):
            receipt = review_gate_lifetime(g, pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assertEqual(receipt.reason, "changed")
        self.assertGreaterEqual(calls[0], 1)
        self.check_no_authority(receipt)

    def test_scope_four_fields_mutated_in_place_all_deny(self):
        scope_changes = (
            ("allow_private_lab", False),
            ("explicit_hosts", frozenset({"fictional.example.test"})),
            ("explicit_networks", ("192.0.2.0/24",)),
            ("require_authorization_for_public", False),
        )
        for field_name, changed_value in scope_changes:
            with self.subTest(field=field_name):
                g = gate()
                pin = pin_gate_for_offline_review(g)
                object.__setattr__(g.scope_policy, field_name, changed_value)
                receipt = review_gate_lifetime(g, pin)
                self.assertIs(receipt.status, LifetimeStatus.HOLD)
                self.check_no_authority(receipt)

    def test_activation_two_fields_mutated_in_place_all_deny(self):
        for field_name, changed_value in (
            ("mode", ActivationMode.LAB_ONLY),
            ("activation_reference", "FICTIONAL-LAB"),
        ):
            with self.subTest(field=field_name):
                g = gate()
                pin = pin_gate_for_offline_review(g)
                object.__setattr__(g.activation_policy, field_name, changed_value)
                receipt = review_gate_lifetime(g, pin)
                self.assertIs(receipt.status, LifetimeStatus.HOLD)
                self.check_no_authority(receipt)

    def test_unchanged_review_preserves_every_source_policy_field(self):
        g = gate(
            scope=ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"fictional.example.test"}),
                explicit_networks=("192.0.2.0/24",),
                require_authorization_for_public=True,
            ),
            activation=ActivationPolicy(ActivationMode.AUTHORIZED, "FAKE-AUTH"),
        )
        original_scope = dict(vars(g.scope_policy))
        original_activation = dict(vars(g.activation_policy))
        pin = pin_gate_for_offline_review(g)
        for _ in range(10):
            receipt = review_gate_lifetime(g, pin)
            self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
            self.check_no_authority(receipt)
        self.assertEqual(vars(g.scope_policy), original_scope)
        self.assertEqual(vars(g.activation_policy), original_activation)

    def test_receipt_constructor_cannot_enable_any_authority_flag(self):
        flags = (
            "may_issue_permit", "may_issue_grant", "may_dispatch",
            "may_scan", "may_deploy", "may_release",
        )
        for flag in flags:
            with self.subTest(flag=flag):
                with self.assertRaises(TypeError):
                    LifetimeReceipt(
                        status=LifetimeStatus.REVIEW_ONLY,
                        reason="unchanged",
                        **{flag: True},
                    )
        control = LifetimeReceipt(LifetimeStatus.REVIEW_ONLY, "unchanged")
        self.check_no_authority(control)

    def test_receipt_normal_field_assignment_is_forbidden(self):
        result = LifetimeReceipt(LifetimeStatus.REVIEW_ONLY, "unchanged")
        with self.assertRaises(FrozenInstanceError):
            result.may_scan = True
        with self.assertRaises(FrozenInstanceError):
            result.status = LifetimeStatus.HOLD
        self.check_no_authority(result)

    def test_receipt_and_snapshot_repr_never_repeat_raw_policy_data(self):
        secret = "FAKE-CONFIDENTIAL-" + "X" * 70
        g = gate(
            scope=ScopePolicy(explicit_hosts=frozenset({"fictional.example.test"})),
            activation=ActivationPolicy(ActivationMode.AUTHORIZED, secret),
        )
        pin = pin_gate_for_offline_review(g)
        receipt = review_gate_lifetime(g, pin)
        self.assertNotIn(secret, repr(pin))
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn("fictional.example.test", repr(pin))
        self.check_no_authority(receipt)


if __name__ == "__main__":
    unittest.main()
