"""Standalone verifier contract; uses synthetic unittest suites, no targets."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

from scripts import verify_trusted_destination_manifest_1093 as verifier


class TestOfflineVerificationContract(unittest.TestCase):
    def setUp(self):
        self.assertEqual(verifier.EXPECTED_TEST_METHODS, 91)

    @staticmethod
    def _suite(test_cls, count=91):
        return unittest.TestSuite(test_cls() for _ in range(count))

    def _call(self, suite=None, *, during_discovery=None):
        output = io.StringIO()
        def discover(*_args, **_kwargs):
            if during_discovery:
                during_discovery()
            return suite
        with (patch.object(sys, "argv", ["verify_trusted_destination_manifest_1093.py"]),
              patch.object(verifier.unittest.TestLoader, "discover", side_effect=discover),
              patch.object(verifier, "_has_expected_test_roster", return_value=True),
              redirect_stdout(output)):
            result = verifier.main()
        rows = output.getvalue().splitlines()
        self.assertEqual(len(rows), 1)
        data = json.loads(rows[0])
        self.assertEqual(data["status"], "hold")
        for flag in ("authorization_verified", "permit_issued", "execution_enabled", "release_approved"):
            self.assertIs(data[flag], False)
        return result, data, rows[0]

    def test_discard_output_remains_constant_space(self):
        sink = verifier._DiscardOutput()
        self.assertEqual(sink.write("password=SECRET" * 200000), 3000000)
        self.assertIsNone(sink.flush())
        self.assertFalse(hasattr(sink, "getvalue"))

    def test_successful_rehearsal_is_always_hold(self):
        class Case(unittest.TestCase):
            def runTest(self):
                print("SYNTHETIC_ONLY_SECRET")
        exit_code, data, line = self._call(self._suite(Case))
        self.assertEqual(exit_code, 0)
        self.assertTrue(data["offline_regression_passed"])
        self.assertEqual(data["tests_run"], 91)
        self.assertEqual(data["errors"], 0)
        self.assertNotIn("SYNTHETIC_ONLY_SECRET", line)

    def test_only_90_tests_is_fail_closed(self):
        class Case(unittest.TestCase):
            def runTest(self):
                pass
        code, data, _ = self._call(self._suite(Case, 90))
        self.assertEqual(code, 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertEqual(data["tests_run"], 90)

    def test_skipped_tests_are_not_success(self):
        class Case(unittest.TestCase):
            @unittest.skip("synthetic")
            def runTest(self):
                raise AssertionError("not entered")
        code, data, _ = self._call(self._suite(Case))
        self.assertEqual(code, 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertEqual(data["skipped"], 91)

    def test_expected_failure_is_not_a_green_result(self):
        class Case(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("synthetic expected failure")
        code, data, line = self._call(self._suite(Case))
        self.assertEqual(code, 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertEqual(data["expected_failures"], 91)
        self.assertEqual(data["unexpected_successes"], 0)
        self.assertNotIn("synthetic expected failure", line)

    def test_unexpected_success_is_not_a_green_result(self):
        class Case(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                pass
        code, data, line = self._call(self._suite(Case))
        self.assertEqual(code, 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertEqual(data["unexpected_successes"], 1)
        self.assertEqual(data["expected_failures"], 0)
        self.assertNotIn("unexpected success", line)

    def test_failed_test_is_sanitized_and_denied(self):
        class Case(unittest.TestCase):
            def runTest(self):
                self.fail("synthetic-secret-must-not-leak")
        code, data, line = self._call(self._suite(Case))
        self.assertEqual(code, 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertEqual(data["failures"], 1)
        self.assertNotIn("synthetic-secret", line)

    def test_import_time_dns_attempt_is_blocked(self):
        def attempt_dns():
            socket.getaddrinfo("localhost", 80)
        code, data, line = self._call(during_discovery=attempt_dns)
        self.assertEqual(code, 1)
        self.assertEqual(data["errors"], 1)
        self.assertNotIn("offline test boundary", line)

    def test_test_time_subprocess_attempt_is_blocked(self):
        class Case(unittest.TestCase):
            def runTest(self):
                import subprocess
                subprocess.run(["/bin/false"], check=True)
        code, data, line = self._call(self._suite(Case))
        self.assertEqual(code, 1)
        self.assertEqual(data["errors"], 1)
        self.assertNotIn("offline test boundary", line)

    def test_external_arguments_are_rejected(self):
        output = io.StringIO()
        with (patch.object(sys, "argv", ["checker", "--target", "example.test"]),
              redirect_stdout(output)):
            code = verifier.main()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "hold")

    def test_missing_tests_is_rejected_before_discovery(self):
        output = io.StringIO()
        with (patch.object(sys, "argv", ["checker"]),
              patch.object(Path, "is_file", return_value=False),
              redirect_stdout(output)):
            code = verifier.main()
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.getvalue())["offline_regression_passed"])

    def test_roster_rejects_correct_count_but_wrong_class(self):
        class Case(unittest.TestCase):
            def runTest(self):
                pass
        self.assertFalse(verifier._has_expected_test_roster(self._suite(Case)))

    def test_roster_accepts_all_91_unique_expected_methods_only(self):
        # This is a synthetic class; it does not execute real LightUp tests.
        class_name = "TestTrustedDestinationMetadata1093"
        methods = {f"test_{i:02d}_synthetic": lambda self: None
                   for i in range(1, 92)}
        cls = type(class_name, (unittest.TestCase,), methods)
        cls.__module__ = "test_trusted_destination_manifest_optin_1093"
        suite = unittest.TestSuite(cls(name) for name in methods)
        self.assertTrue(verifier._has_expected_test_roster(suite))
        # Duplicate one case number, replacing another case.
        broken = unittest.TestSuite([cls(name) for name in list(methods)[:-1]]
                                    + [cls("test_01_synthetic")])
        self.assertFalse(verifier._has_expected_test_roster(broken))

    def test_end_to_end_synthetic_exact_roster_yields_only_hold(self):
        methods = {f"test_{i:02d}_synthetic": lambda self: print("PRIVATE_FIXTURE")
                   for i in range(1, 92)}
        cls = type("TestTrustedDestinationMetadata1093", (unittest.TestCase,), methods)
        cls.__module__ = "test_trusted_destination_manifest_optin_1093"
        suite = unittest.TestSuite(cls(name) for name in methods)
        output = io.StringIO()
        with (patch.object(sys, "argv", ["checker"]),
              patch.object(verifier.unittest.TestLoader, "discover", return_value=suite),
              redirect_stdout(output)):
            exit_code = verifier.main()
        self.assertEqual(exit_code, 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["tests_run"], 91)
        self.assertTrue(data["offline_regression_passed"])
        self.assertEqual(data["status"], "hold")
        self.assertIs(data["permit_issued"], False)
        self.assertNotIn("PRIVATE_FIXTURE", output.getvalue())

    def test_end_to_end_duplicate_roster_fails_before_test_execution(self):
        executed = []
        def record(self):
            executed.append(True)
        methods = {f"test_{i:02d}_synthetic": record for i in range(1, 92)}
        cls = type("TestTrustedDestinationMetadata1093", (unittest.TestCase,), methods)
        cls.__module__ = "test_trusted_destination_manifest_optin_1093"
        suite = unittest.TestSuite([cls(name) for name in list(methods)[:-1]]
                                   + [cls("test_01_synthetic")])
        output = io.StringIO()
        with (patch.object(sys, "argv", ["checker"]),
              patch.object(verifier.unittest.TestLoader, "discover", return_value=suite),
              redirect_stdout(output)):
            exit_code = verifier.main()
        self.assertEqual(exit_code, 1)
        self.assertEqual(executed, [])
        data = json.loads(output.getvalue())
        self.assertFalse(data["offline_regression_passed"])
        self.assertIs(data["execution_enabled"], False)

    def test_end_to_end_valid_roster_cannot_call_dns(self):
        def safe(self):
            pass
        def attempt(self):
            socket.getaddrinfo("localhost", 80)
        methods = {f"test_{i:02d}_synthetic": (attempt if i == 1 else safe)
                   for i in range(1, 92)}
        cls = type("TestTrustedDestinationMetadata1093", (unittest.TestCase,), methods)
        cls.__module__ = "test_trusted_destination_manifest_optin_1093"
        suite = unittest.TestSuite(cls(name) for name in methods)
        output = io.StringIO()
        with (patch.object(sys, "argv", ["checker"]),
              patch.object(verifier.unittest.TestLoader, "discover", return_value=suite),
              redirect_stdout(output)):
            exit_code = verifier.main()
        self.assertEqual(exit_code, 1)
        data = json.loads(output.getvalue())
        self.assertEqual(data["errors"], 1)
        self.assertFalse(data["offline_regression_passed"])
        self.assertIs(data["authorization_verified"], False)

    def test_receipt_factory_never_promotes_authority(self):
        receipt = verifier._receipt(True, 91)
        self.assertTrue(receipt["offline_regression_passed"])
        for key in ("authorization_verified", "permit_issued", "execution_enabled", "release_approved"):
            self.assertIs(receipt[key], False)


if __name__ == "__main__":
    unittest.main()
