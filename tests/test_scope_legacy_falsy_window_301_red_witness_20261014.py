"""Assert that #301 expected-RED tests are failing assertions, not masked crashes."""
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


def _require_assertion_witnesses(testcase, result):
    testcase.assertEqual(result.testsRun, len(RED_METHODS))
    testcase.assertFalse(result.errors)
    testcase.assertFalse(result.failures)
    testcase.assertFalse(result.unexpectedSuccesses)
    testcase.assertEqual(len(result.expectedFailures), len(RED_METHODS))
    testcase.assertEqual(
        {case._testMethodName for case, _ in result.expectedFailures},
        set(RED_METHODS),
    )
    for _, trace in result.expectedFailures:
        testcase.assertIn("AssertionError:", trace)
        for forbidden in ("TypeError:", "ValueError:", "AttributeError:", "KeyError:"):
            testcase.assertNotIn(forbidden, trace)


class LegacyFalsyBoundaryWitnessTests(unittest.TestCase):
    def test_all_ten_expected_red_witnesses_are_assertion_failures(self):
        for name in RED_METHODS:
            self.assertTrue(getattr(
                red.LegacyFalsyBoundaryRedTests.__dict__[name],
                "__unittest_expecting_failure__", False
            ), name)
        result = unittest.TestResult()
        unittest.TestSuite([
            red.LegacyFalsyBoundaryRedTests(name) for name in RED_METHODS
        ]).run(result)
        _require_assertion_witnesses(self, result)

    def test_masked_crash_fails_witness_gate(self):
        class Fake:
            _testMethodName = RED_METHODS[0]

        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.expectedFailures = [
            (Fake(), "Traceback\nTypeError: intentionally unrelated")
            for _ in RED_METHODS
        ]
        with self.assertRaises(AssertionError):
            _require_assertion_witnesses(self, result)

    def test_unexpected_success_fails_witness_gate(self):
        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.unexpectedSuccesses = [object()]
        with self.assertRaises(AssertionError):
            _require_assertion_witnesses(self, result)


if __name__ == "__main__":
    unittest.main()
