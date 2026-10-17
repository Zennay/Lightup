"""Keep #301's formerly-RED falsy-window canaries fixed (no expectedFailure)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import test_scope_legacy_falsy_window_301_red_20261014 as red


RED_METHODS = (
    "test_red_zero_expiry_is_not_unbounded",
    "test_red_false_expiry_is_not_unbounded",
    "test_red_empty_text_expiry_is_not_unbounded",
    "test_red_empty_tuple_expiry_is_not_unbounded",
    "test_red_zero_start_is_not_unbounded",
    "test_red_false_start_is_not_unbounded",
    "test_red_empty_text_start_is_not_unbounded",
    "test_red_empty_tuple_start_is_not_unbounded",
    "test_red_false_expiry_must_not_authorize_scope",
    "test_red_zero_expiry_must_not_authorize_scope",
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
                getattr(red.LegacyFalsyBoundaryRedTests.__dict__[method],
                        "__unittest_expecting_failure__", False),
                f"{method} is fixed and must not be re-marked RED",
            )
        result = unittest.TestResult()
        unittest.TestSuite([red.LegacyFalsyBoundaryRedTests(m) for m in RED_METHODS]).run(result)
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
