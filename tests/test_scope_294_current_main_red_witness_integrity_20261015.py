"""Issue #294: verify that each installed expected-RED is a genuine assertion.

@unittest.expectedFailure considers *any* exception a passing expected failure.
A TypeError, import regression or I/O failure could therefore mask genuine
security-test breakage. This independent verifier pins the six source test
identities and checks their captured failure reasons. Nothing is authorized.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
from test_scope_294_current_main_mutable_alias_red_20261015 import (
    MutableScopePolicyInputIdentityTests,
)

RED_CASES = (
    "test_red_mutable_host_set_must_be_snapshotted_at_construction",
    "test_red_mutable_host_set_must_not_widen_after_construction",
    "test_red_mutable_host_set_must_not_narrow_after_construction",
    "test_red_mutable_network_list_must_be_snapshotted_at_construction",
    "test_red_mutable_network_list_must_not_widen_after_construction",
    "test_red_mutable_network_list_must_not_narrow_after_construction",
)


def _run(case_type: type[unittest.TestCase], method_names: tuple[str, ...]):
    suite = unittest.TestSuite(case_type(name) for name in method_names)
    result = unittest.TestResult()
    suite.run(result)
    return result


def _all_real_assertion_reds(result: unittest.TestResult, expected: int) -> bool:
    """A synthetic result shape gate; never a license to execute anything."""
    if not (
        result.testsRun == expected
        and len(result.expectedFailures) == expected
        and not result.failures
        and not result.errors
        and not result.unexpectedSuccesses
        and not result.skipped
    ):
        return False
    seen = set()
    for case, formatted in result.expectedFailures:
        if type(formatted) is not str:
            return False
        case_id = case.id()
        if case_id in seen:
            return False
        seen.add(case_id)
        if "AssertionError:" not in formatted:
            return False
        # Unexpected execution errors are not security acceptance evidence.
        for type_name in (
            "TypeError:", "AttributeError:", "ImportError:",
            "RuntimeError:", "OSError:", "TimeoutError:",
            "PermissionError:", "ConnectionError:",
        ):
            if type_name in formatted:
                return False
    return len(seen) == expected


class InstalledScopeMutationRedWitnessIntegrityTests(unittest.TestCase):
    def test_exact_six_source_canaries_are_assertion_red_not_error(self):
        case_methods = {
            name for name in dir(MutableScopePolicyInputIdentityTests)
            if name.startswith("test_red_")
        }
        self.assertEqual(case_methods, set(RED_CASES))
        result = _run(MutableScopePolicyInputIdentityTests, RED_CASES)
        self.assertTrue(
            _all_real_assertion_reds(result, 6),
            "six installed security canaries must fail on assertions, not errors",
        )
        self.assertEqual(
            {case._testMethodName for case, _ in result.expectedFailures},
            set(RED_CASES),
        )

    def test_type_error_must_not_be_accepted_as_expected_security_red(self):
        class BrokenWitness(unittest.TestCase):
            @unittest.expectedFailure
            def test_red(self):
                raise TypeError("test harness malformed")
        result = _run(BrokenWitness, ("test_red",))
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertFalse(_all_real_assertion_reds(result, 1))

    def test_unexpected_green_must_fail_security_witness_gate(self):
        class AccidentallyRepaired(unittest.TestCase):
            @unittest.expectedFailure
            def test_red(self):
                self.assertEqual(1, 1)
        result = _run(AccidentallyRepaired, ("test_red",))
        self.assertEqual(len(result.unexpectedSuccesses), 1)
        self.assertFalse(_all_real_assertion_reds(result, 1))

    def test_expected_red_witnesses_remain_fully_in_memory(self):
        with patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            result = _run(MutableScopePolicyInputIdentityTests, RED_CASES)
        self.assertTrue(_all_real_assertion_reds(result, 6))


if __name__ == "__main__":
    unittest.main()
