"""Witness integrity for issue #647 expected RED without masking runtime failures."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import test_scope_grant_issuance_datetime_647_red_20261014 as red

RED = (
    "test_red_overridden_expiry_serializer_must_be_refused_at_issuance",
    "test_red_overridden_start_serializer_must_be_refused_at_issuance",
    "test_red_durable_expiry_must_not_exceed_original_exact_instant",
    "test_red_durable_start_must_not_predate_original_exact_instant",
)


class IssuanceDatetimeWitnessTests(unittest.TestCase):
    def test_expected_failures_are_actual_assertion_red_not_hidden_errors(self):
        for method in RED:
            self.assertTrue(getattr(
                red.PersistedGrantDatetimeIssuanceRedTests.__dict__[method],
                "__unittest_expecting_failure__", False
            ))
        private_result = unittest.TestResult()
        unittest.TestSuite([
            red.PersistedGrantDatetimeIssuanceRedTests(method) for method in RED
        ]).run(private_result)
        self.assertEqual(private_result.testsRun, len(RED))
        self.assertFalse(private_result.errors)
        self.assertFalse(private_result.failures)
        self.assertFalse(private_result.unexpectedSuccesses)
        self.assertEqual(len(private_result.expectedFailures), len(RED))
        self.assertEqual(
            {case._testMethodName for case, _ in private_result.expectedFailures},
            set(RED),
        )
        for _, trace in private_result.expectedFailures:
            self.assertIn("AssertionError:", trace)
            for accidental in ("TypeError:", "ValueError:", "AttributeError:", "sqlite3."):
                self.assertNotIn(accidental, trace)


if __name__ == "__main__":
    unittest.main()
