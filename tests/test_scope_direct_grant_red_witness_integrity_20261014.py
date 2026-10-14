"""Guard against expectedFailure silently hiding crashes in #738's RED canaries.

This is a synthetic unittest meta-check. No network, target, executor,
filesystem write, credential, authorization, or production source modification.
"""
import os
import re
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


def _assert_true_red(testcase, result):
    """Refuse masked non-assertion exception or accidental green XPASS."""
    testcase.assertEqual(result.testsRun, len(RED_METHODS))
    testcase.assertFalse(result.errors)
    testcase.assertFalse(result.failures)
    testcase.assertFalse(result.unexpectedSuccesses)
    testcase.assertEqual(len(result.expectedFailures), len(RED_METHODS))
    testcase.assertEqual(
        {test._testMethodName for test, _ in result.expectedFailures},
        set(RED_METHODS),
    )
    for _, trace in result.expectedFailures:
        testcase.assertRegex(trace, r"(?m)^AssertionError(?::|\\b)")
        # Unexpected source/API crashes are not meaningful authorization witnesses.
        testcase.assertNotRegex(trace, r"(?m)^(?:TypeError|ValueError|AttributeError|ImportError|KeyError):")


class ExpectedRedWitnessIntegrityTests(unittest.TestCase):
    def test_expected_red_canaries_are_actual_assertion_failures(self):
        for method in RED_METHODS:
            self.assertTrue(
                getattr(red.DirectGrantDatetimeIdentityTests.__dict__[method],
                        "__unittest_expecting_failure__", False),
                f"{method} must stay explicitly marked RED until the source-owner fix",
            )
        cases = [red.DirectGrantDatetimeIdentityTests(method) for method in RED_METHODS]
        result = unittest.TestResult()
        unittest.TestSuite(cases).run(result)
        _assert_true_red(self, result)

    def test_classifier_rejects_forged_runtime_error_evidence(self):
        class FakeCase:
            _testMethodName = RED_METHODS[0]

        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.expectedFailures = [
            (FakeCase(), "Traceback (most recent call last):\\nTypeError: crash")
            for _ in RED_METHODS
        ]
        with self.assertRaises(AssertionError):
            _assert_true_red(self, result)

    def test_classifier_rejects_unexpected_success(self):
        result = unittest.TestResult()
        result.testsRun = len(RED_METHODS)
        result.unexpectedSuccesses = [object()]
        with self.assertRaises(AssertionError):
            _assert_true_red(self, result)


if __name__ == "__main__":
    unittest.main()
