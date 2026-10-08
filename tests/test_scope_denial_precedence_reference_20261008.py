"""Offline reference tests for fail-closed authorization denial precedence.

This is an illustrative acceptance contract, NOT a production policy implementation.
No sockets, DNS, targets, workflow dispatch, or authorization activation.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Input:
    authenticated: bool = False
    tenant_matches: bool = False
    grant_active: bool = False
    window_valid: bool = False
    scope_matches: bool = False
    capability_allowed: bool = False
    risk_allowed: bool = False


# Only positive, exact bool flags count; a truthy string or int never grants access.
CHECKS = (
    ("authenticated", "unauthenticated"),
    ("tenant_matches", "tenant_denied"),
    ("grant_active", "inactive_grant"),
    ("window_valid", "invalid_window"),
    ("scope_matches", "scope_denied"),
    ("capability_allowed", "capability_denied"),
    ("risk_allowed", "risk_denied"),
)


def decide(value):
    if type(value) is not Input:
        return False, "invalid_request"
    for field, reason in CHECKS:
        if getattr(value, field) is not True:
            return False, reason
    return True, "conditionally_eligible"


class DenialPrecedenceReferenceTests(unittest.TestCase):
    def test_complete_positive_path_is_only_conditionally_eligible(self):
        self.assertEqual(decide(Input(*([True] * 7))), (True, "conditionally_eligible"))

    def test_every_gate_fails_individually(self):
        for index, (_, reason) in enumerate(CHECKS):
            flags = [True] * 7
            flags[index] = False
            with self.subTest(reason=reason):
                self.assertEqual(decide(Input(*flags)), (False, reason))

    def test_earliest_failure_wins_independent_of_later_flags(self):
        for index, (_, reason) in enumerate(CHECKS):
            flags = [True] * index + [False] * (7 - index)
            with self.subTest(reason=reason):
                self.assertEqual(decide(Input(*flags)), (False, reason))

    def test_truthy_non_booleans_are_denied_at_each_gate(self):
        for impostor in (1, "true", [True]):
            for index, (_, reason) in enumerate(CHECKS):
                flags = [True] * 7
                flags[index] = impostor
                with self.subTest(value=repr(impostor), gate=reason):
                    self.assertEqual(decide(Input(*flags)), (False, reason))

    def test_invalid_input_has_priority_over_gate_details(self):
        self.assertEqual(decide({"authenticated": True}), (False, "invalid_request"))
        self.assertEqual(decide(None), (False, "invalid_request"))

    def test_subclass_does_not_inherit_permission(self):
        class Spoof(Input):
            pass
        self.assertEqual(decide(Spoof(*([True] * 7))), (False, "invalid_request"))

    def test_denial_is_deterministic_and_input_unchanged(self):
        sample = Input(True, True, True, True, False, True, True)
        snapshot = repr(sample)
        self.assertEqual([decide(sample)] * 3, [decide(sample) for _ in range(3)])
        self.assertEqual(repr(sample), snapshot)


    def test_all_128_boolean_combinations_preserve_first_denial(self):
        from itertools import product
        for flags in product((False, True), repeat=len(CHECKS)):
            with self.subTest(flags=flags):
                expected = next(
                    ((False, reason) for flag, (_, reason) in zip(flags, CHECKS) if not flag),
                    (True, "conditionally_eligible"),
                )
                self.assertEqual(decide(Input(*flags)), expected)

    def test_only_literal_true_can_advance_a_gate(self):
        for impostor in (True, 1, "true", [True], False, None):
            flags = [True] * len(CHECKS)
            flags[0] = impostor
            with self.subTest(impostor=repr(impostor)):
                expected = (True, "conditionally_eligible") if impostor is True else (False, "unauthenticated")
                self.assertEqual(decide(Input(*flags)), expected)

if __name__ == "__main__":
    unittest.main()
