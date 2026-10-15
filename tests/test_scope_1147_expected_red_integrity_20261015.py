"""Independent #1147 xfail-integrity oracle — synthetic, no authority.

unittest.expectedFailure treats *any* exception as expected, so a crash in
SQLite, policy, an inert handler, or test setup can falsely look like a
meaningful source RED. This test independently runs the exact owned 25-case
installed-ToolExecutor matrix and demands nine PARTICULAR missing-denial
assertions. Any other traceback, omission, unexpected success, skipped method,
network guard failure, or regression is an ordinary test failure.

No customer data, runtime source, target access, sockets or grants.
"""
from __future__ import annotations

import sys
import unittest

# Pin each regression to a concrete original-source weakness; do not derive
# the denominator from what the test loader happens to discover.
EXPECTED_SOURCE_RED = frozenset({
    "test_required_denial_of_duplicate_optional_keys_before_any_effect",
    "test_required_denial_of_duplicate_type_confusion_before_any_effect",
    "test_required_denial_of_duplicate_valid_keys_before_any_effect",
    "test_required_denial_of_identical_duplicate_keys_before_any_effect",
    "test_required_denial_of_interleaved_triple_keys_before_any_effect",
    "test_required_duplicate_rejects_before_schema_validation_or_policy",
    "test_required_order_alpha_then_beta_is_denied_before_any_effect",
    "test_required_order_beta_then_alpha_is_denied_before_any_effect",
    "test_required_rejected_duplicate_preserves_prior_committed_evidence",
})
EXPECTED_TOTAL = 25
EXPECTED_ORDINARY = 16
EXACT_RED_SIGNATURE = "AssertionError: OrchestrationError not raised"


def verify_source_red_receipt(
    result: unittest.TestResult,
    *,
    expected_red: frozenset[str] = EXPECTED_SOURCE_RED,
    expected_total: int = EXPECTED_TOTAL,
    expected_ordinary: int = EXPECTED_ORDINARY,
) -> None:
    """Raise AssertionError unless an installed-source test RED is *specific*.

    This is deliberately NOT an authorization decision. A future source repair
    should make it FAIL until the owner converts RED to ordinary PASS.
    """
    if result.testsRun != expected_total:
        raise AssertionError("scope-1147 matrix method count changed")
    if result.failures or result.errors or result.unexpectedSuccesses or result.skipped:
        raise AssertionError("scope-1147 matrix has unexpected failures/results")
    observed = [case.id().rsplit(".", 1)[-1] for case, _ in result.expectedFailures]
    if len(observed) != len(expected_red) or set(observed) != expected_red:
        raise AssertionError("scope-1147 expected-RED identities changed")
    if result.testsRun - len(observed) != expected_ordinary:
        raise AssertionError("scope-1147 ordinary control count changed")
    for case, failure in result.expectedFailures:
        method_name = case.id().rsplit(".", 1)[-1]
        # A substring match is unsafe: ValueError("AssertionError:
        # OrchestrationError not raised") used to pass as a valid source RED.
        # Require the *final exception type and message*, not text elsewhere
        # inside an unrelated crash or nested traceback.
        if failure.strip().splitlines()[-1] != EXACT_RED_SIGNATURE:
            raise AssertionError(
                "scope-1147 source RED masked a different exception: " + method_name
            )
        # The source RED must be raised inside its own installed-executor
        # regression test. This also rejects fake TestResult receipts carrying
        # a correct-looking final assertion but a mismatched traceback.
        if (
            "test_scope_1147_duplicate_key_installed_matrix_20261015.py" not in failure
            or f"in {method_name}" not in failure
        ):
            raise AssertionError(
                "scope-1147 source RED traceback provenance invalid: " + method_name
            )


class Scope1147ExpectedRedIntegrityTests(unittest.TestCase):
    def test_exact_original_source_red_signatures_and_all_controls(self):
        # Import only inside the meta-test: unittest discover would otherwise
        # auto-collect this imported TestCase *again* from this module.
        from test_scope_1147_duplicate_key_installed_matrix_20261015 import (
            DuplicateArgumentKeysInstalledSource1147,
        )
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            DuplicateArgumentKeysInstalledSource1147
        )
        result = unittest.TestResult()
        suite.run(result)
        verify_source_red_receipt(result)

    def test_unittest_discovery_does_not_collect_25_source_cases_twice(self):
        module = sys.modules[__name__]
        self.assertNotIn(
            "DuplicateArgumentKeysInstalledSource1147", vars(module),
            "module-level imported TestCase silently duplicates test discovery",
        )
        discovered = unittest.defaultTestLoader.loadTestsFromModule(module)

        def flatten(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item

        cases = list(flatten(discovered))
        self.assertEqual(len(cases), 8)
        self.assertTrue(
            all(type(case) is Scope1147ExpectedRedIntegrityTests for case in cases)
        )

    def test_validator_rejects_fake_expected_failure_from_crash(self):
        class BrokenReference(unittest.TestCase):
            @unittest.expectedFailure
            def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
                raise RuntimeError("unexpected setup fault")

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(BrokenReference).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        with self.assertRaisesRegex(AssertionError, "masked a different exception"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({
                    "test_required_denial_of_duplicate_valid_keys_before_any_effect"
                }),
                expected_total=1,
                expected_ordinary=0,
            )

    def test_validator_rejects_valueerror_containing_fake_source_signature(self):
        class ForgedValueError(unittest.TestCase):
            @unittest.expectedFailure
            def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
                raise ValueError(EXACT_RED_SIGNATURE)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(ForgedValueError).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        with self.assertRaisesRegex(AssertionError, "masked a different exception"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({
                    "test_required_denial_of_duplicate_valid_keys_before_any_effect"
                }),
                expected_total=1, expected_ordinary=0,
            )

    def test_validator_rejects_assertion_with_appended_source_signature(self):
        class ForgedAssertion(unittest.TestCase):
            @unittest.expectedFailure
            def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
                raise AssertionError(EXACT_RED_SIGNATURE + " false receipt")

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(ForgedAssertion).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        with self.assertRaisesRegex(AssertionError, "masked a different exception"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({
                    "test_required_denial_of_duplicate_valid_keys_before_any_effect"
                }),
                expected_total=1, expected_ordinary=0,
            )

    def test_validator_rejects_forged_final_signature_from_another_test_file(self):
        class ForgedProvenance(unittest.TestCase):
            @unittest.expectedFailure
            def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
                raise AssertionError("OrchestrationError not raised")

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(ForgedProvenance).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        with self.assertRaisesRegex(AssertionError, "traceback provenance invalid"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({
                    "test_required_denial_of_duplicate_valid_keys_before_any_effect"
                }),
                expected_total=1, expected_ordinary=0,
            )

    def test_validator_rejects_fixed_source_claimed_as_expected_red(self):
        class FixedSource(unittest.TestCase):
            @unittest.expectedFailure
            def test_required_denial_of_duplicate_valid_keys_before_any_effect(self):
                self.assertTrue(True)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(FixedSource).run(result)
        self.assertEqual(len(result.unexpectedSuccesses), 1)
        with self.assertRaisesRegex(AssertionError, "unexpected failures/results"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({
                    "test_required_denial_of_duplicate_valid_keys_before_any_effect"
                }),
                expected_total=1,
                expected_ordinary=0,
            )

    def test_validator_rejects_dropped_expected_red_contract(self):
        class Ordinary(unittest.TestCase):
            def test_normal(self):
                self.assertTrue(True)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Ordinary).run(result)
        with self.assertRaisesRegex(AssertionError, "expected-RED identities changed"):
            verify_source_red_receipt(
                result,
                expected_red=frozenset({"test_missing_red"}),
                expected_total=1,
                expected_ordinary=0,
            )


if __name__ == "__main__":
    unittest.main()
