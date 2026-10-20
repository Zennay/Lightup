"""Keep #738's formerly-RED direct-grant canaries fixed (no expectedFailure).

This is a synthetic unittest meta-check. No network, target, executor,
filesystem write, credential, authorization, or production source modification.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import test_scope_direct_grant_datetime_identity_red_20261014 as red


RED_METHODS = (
    "test_red_future_lower_bound_polymorphic_datetime_must_fail_closed",
    "test_red_expired_upper_bound_polymorphic_datetime_must_fail_closed",
    "test_red_both_polymorphic_datetime_bounds_must_fail_closed",
    "test_red_future_subclass_is_rejected_by_live_execution_policy",
    "test_red_expired_subclass_is_rejected_by_live_execution_policy",
)


def _assert_fixed(testcase, result):
    """Formerly-RED canaries must now pass: no errors, failures or XFAILs."""
    testcase.assertEqual(result.testsRun, len(RED_METHODS))
    testcase.assertFalse(result.errors)
    testcase.assertFalse(result.failures)
    testcase.assertFalse(result.expectedFailures)
    testcase.assertFalse(result.unexpectedSuccesses)


class FixedRedWitnessTests(unittest.TestCase):
    def test_formerly_red_canaries_pass_without_expected_failure(self):
        for method in RED_METHODS:
            self.assertFalse(
                getattr(red.DirectGrantDatetimeIdentityTests.__dict__[method],
                        "__unittest_expecting_failure__", False),
                f"{method} is fixed and must not be re-marked RED",
            )
        result = unittest.TestResult()
        unittest.TestSuite([red.DirectGrantDatetimeIdentityTests(m) for m in RED_METHODS]).run(result)
        _assert_fixed(self, result)

    def test_gate_rejects_regression_back_to_expected_failure(self):
        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.expectedFailures = [(object(), "AssertionError: regressed")]
        with self.assertRaises(AssertionError):
            _assert_fixed(self, result)

    def test_gate_rejects_errors(self):
        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.errors = [(object(), "TypeError: crash")]
        with self.assertRaises(AssertionError):
            _assert_fixed(self, result)


if __name__ == "__main__":
    unittest.main()
