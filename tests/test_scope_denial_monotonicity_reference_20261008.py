"""Offline reference regression: an added denial cannot authorize execution.

This is deliberately not the production authorization implementation.
No network requests, target access, or side effects.
"""
import itertools
import unittest

GATES = ("tenant_active", "grant_current", "scope_matches", "review_valid", "not_revoked")


def reference_admission(gates):
    if type(gates) is not dict or set(gates) != set(GATES):
        return False
    return all(type(gates[name]) is bool and gates[name] for name in GATES)


class DenialMonotonicityReferenceTests(unittest.TestCase):
    def test_every_boolean_combination(self):
        for values in itertools.product((False, True), repeat=len(GATES)):
            state = dict(zip(GATES, values))
            self.assertEqual(reference_admission(state), all(values))

    def test_flipping_true_to_false_never_grants(self):
        for values in itertools.product((False, True), repeat=len(GATES)):
            state = dict(zip(GATES, values))
            for name in GATES:
                if state[name]:
                    restricted = {**state, name: False}
                    self.assertFalse(reference_admission(restricted))

    def test_increasing_denials_never_grants(self):
        for values in itertools.product((False, True), repeat=len(GATES)):
            state = dict(zip(GATES, values))
            for mask in itertools.product((False, True), repeat=len(GATES)):
                restricted = {
                    name: value and permitted
                    for name, value, permitted in zip(GATES, values, mask)
                }
                if not reference_admission(state):
                    self.assertFalse(reference_admission(restricted))

    def test_nonboolean_truthy_values_fail_closed(self):
        for value in (1, "true", [], {}, None, (1,), 0):
            for name in GATES:
                state = dict.fromkeys(GATES, True)
                state[name] = value
                self.assertFalse(reference_admission(state))

    def test_missing_or_extra_gate_fail_closed(self):
        baseline = dict.fromkeys(GATES, True)
        for name in GATES:
            state = baseline.copy()
            state.pop(name)
            self.assertFalse(reference_admission(state))
        self.assertFalse(reference_admission({**baseline, "bypass": True}))


    def test_gate_order_does_not_change_admission(self):
        baseline = dict.fromkeys(GATES, True)
        for order in itertools.permutations(GATES):
            self.assertTrue(reference_admission({name: baseline[name] for name in order}))
            denied = {name: (name != "not_revoked") for name in order}
            self.assertFalse(reference_admission(denied))

    def test_no_coercion_of_hostile_truthiness(self):
        class HostileTruth:
            def __bool__(self):
                raise AssertionError("authorization must not coerce untrusted values")

        for name in GATES:
            state = dict.fromkeys(GATES, True)
            state[name] = HostileTruth()
            self.assertFalse(reference_admission(state))

    def test_non_dict_containers_fail_closed(self):
        baseline = dict.fromkeys(GATES, True)
        for candidate in (list(baseline.items()), tuple(baseline.items()), None):
            self.assertFalse(reference_admission(candidate))

        class DictSubclass(dict):
            pass

        self.assertFalse(reference_admission(DictSubclass(baseline)))

    def test_no_input_mutation(self):
        state = dict.fromkeys(GATES, True)
        before = state.copy()
        self.assertTrue(reference_admission(state))
        self.assertEqual(state, before)


if __name__ == "__main__":
    unittest.main()
