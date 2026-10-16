"""Pure, non-authorizing regression tests for the #920 targeted CLI guard.

No customer input, sockets, git subprocesses, active scan or runtime patch.
"""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / (
    "check_scope_920_current_main_acceptance_20261016.py"
)
SPEC = importlib.util.spec_from_file_location("scope_920_acceptance_cli", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class Scope920RunnerProvenanceTest(unittest.TestCase):
    def test_git_blob_encoding_uses_real_nul_framing(self):
        self.assertEqual(
            acceptance.git_blob_id(b"hello"),
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
        )
        self.assertEqual(
            acceptance.git_blob_id(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_current_main_source_matches_immutable_pinned_blob(self):
        self.assertEqual(
            acceptance.PINNED_SOURCE_BLOB,
            "ca657372e43a15f212b3b7c92605f9f29e055531",
        )
        self.assertTrue(acceptance.source_is_pinned())

    def test_wrong_source_bytes_fail_closed_without_network_or_git(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-only-") as temp:
            candidate = Path(temp) / "src" / "lightup" / "webapp"
            candidate.mkdir(parents=True)
            (candidate / "security.py").write_bytes(b"not the installed source")
            with patch.object(acceptance, "ROOT", Path(temp)):
                self.assertFalse(acceptance.source_is_pinned())

    def test_owned_acceptance_tests_match_immutable_blob(self):
        # A fake suite with twenty doctored tests must not get REVIEW_ONLY.
        self.assertEqual(
            acceptance.PINNED_TEST_BLOB,
            "ae63a85546e970a19a9f44489732b45a70448811",
        )
        self.assertTrue(acceptance.acceptance_tests_are_pinned())

    def test_edited_acceptance_tests_are_hold_before_test_discovery(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-own-fixture-") as temp:
            test_dir = Path(temp) / "tests"
            test_dir.mkdir()
            (test_dir / acceptance.PATTERN).write_text(
                "def test_fake_green(): pass\n", encoding="utf-8",
            )
            with patch.object(acceptance, "ROOT", Path(temp)):
                with patch.object(acceptance, "source_is_pinned", return_value=True):
                    self.assertFalse(acceptance.acceptance_tests_are_pinned())
                    with patch.object(acceptance.unittest, "TestLoader") as loader:
                        output = io.StringIO()
                        with patch("sys.stdout", output):
                            self.assertEqual(acceptance.main(), 2)
                        loader.assert_not_called()
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["tests_run"], 0)
            self.assertIs(result["release_authorized"], False)

    def test_missing_or_symlinked_acceptance_tests_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-own-fixture-") as temp:
            root = Path(temp)
            test_dir = root / "tests"
            test_dir.mkdir()
            with patch.object(acceptance, "ROOT", root):
                self.assertFalse(acceptance.acceptance_tests_are_pinned())
                target = test_dir / "target.txt"
                target.write_text("not a real source file", encoding="utf-8")
                (test_dir / acceptance.PATTERN).symlink_to(target)
                self.assertFalse(acceptance.acceptance_tests_are_pinned())

    def test_missing_source_file_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-only-") as temp:
            with patch.object(acceptance, "ROOT", Path(temp)):
                self.assertFalse(acceptance.source_is_pinned())

    def test_wrong_test_count_holds_before_runner_invocation(self):
        output = io.StringIO()
        with patch.object(acceptance, "source_is_pinned", return_value=True):
            with patch.object(acceptance, "acceptance_tests_are_pinned", return_value=True):
                with patch.object(acceptance.unittest, "TestLoader") as loader:
                    loader.return_value.discover.return_value.countTestCases.return_value = 19
                    with patch.object(acceptance.unittest, "TextTestRunner") as runner:
                        with patch("sys.stdout", output):
                            self.assertEqual(acceptance.main(), 2)
                        runner.assert_not_called()
        data = json.loads(output.getvalue())
        self.assertEqual(data["status"], "HOLD")
        self.assertEqual(data["tests_run"], 19)
        self.assertIs(data["release_authorized"], False)

    def test_bad_unit_outcomes_never_yield_review_only(self):
        # Exercise the actual CLI decision function, but replace ONLY the
        # local synthetic TestLoader/runner result; no executor is invoked.
        cases = (
            ("unexpected_success", {"unexpectedSuccesses": ["fixed"]}),
            ("unexpected_skip", {"skipped": ["ignored"]}),
            ("ordinary_failure", {"failures": ["broken"]}),
            ("runtime_error", {"errors": ["broken"]}),
            ("source_red_missing", {"expectedFailures": [None] * 8}),
            ("source_red_extra", {"expectedFailures": [None] * 10}),
            ("wrong_result_count", {"testsRun": 19}),
            ("was_unsuccessful", {"successful": False}),
        )
        for title, changes in cases:
            with self.subTest(case=title):
                output = io.StringIO()
                with patch.object(acceptance, "source_is_pinned", return_value=True):
                    with patch.object(acceptance, "acceptance_tests_are_pinned", return_value=True):
                        with patch.object(acceptance.unittest, "TestLoader") as loader:
                            loader.return_value.discover.return_value.countTestCases.return_value = 20
                            with patch.object(acceptance.unittest, "TextTestRunner") as runner:
                                outcome = runner.return_value.run.return_value
                                outcome.wasSuccessful.return_value = changes.get("successful", True)
                                outcome.testsRun = changes.get("testsRun", 20)
                                outcome.expectedFailures = changes.get("expectedFailures", [None] * 9)
                                outcome.unexpectedSuccesses = changes.get("unexpectedSuccesses", [])
                                outcome.skipped = changes.get("skipped", [])
                                outcome.failures = changes.get("failures", [])
                                outcome.errors = changes.get("errors", [])
                                # unittest's wasSuccessful should normally reflect
                                # failures; the CLI must not trust it blindly.
                                with patch("sys.stdout", output):
                                    status = acceptance.main()
                receipt = json.loads(output.getvalue())
                self.assertEqual(status, 2)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertIs(receipt["merge_authorized"], False)
                self.assertIs(receipt["release_authorized"], False)

    def test_real_offline_runner_executes_all_twenty_but_never_releases(self):
        # Drive the *real* opt-in runner in process on the pinned current-main
        # WebSecurity source, nested inside this separate provenance test.
        # No subprocess, socket, external target, or dispatch can be reached.
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            exit_code = acceptance.main()
        self.assertEqual(exit_code, 0, stderr.getvalue()[-1200:])
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["tests_run"], 20)
        self.assertEqual(result["expected_source_failures"], 9)
        for field in (
            "release_authorized", "merge_authorized", "scan_authorized",
            "dispatch_authorized", "registered_vps_verified",
            "full_suite_verified", "client_operator_consent_verified",
            "source_fixed",
        ):
            with self.subTest(field=field):
                self.assertIs(result[field], False)

    def test_source_drift_does_not_run_tests_or_grant_any_authority(self):
        output = io.StringIO()
        with patch.object(acceptance, "source_is_pinned", return_value=False):
            with patch.object(acceptance.unittest, "TestLoader") as loader:
                with patch("sys.stdout", output):
                    self.assertEqual(acceptance.main(), 2)
                loader.assert_not_called()
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["tests_run"], 0)
        for field in (
            "source_fixed", "release_authorized", "merge_authorized",
            "scan_authorized", "dispatch_authorized", "registered_vps_verified",
            "full_suite_verified", "client_operator_consent_verified",
        ):
            with self.subTest(field=field):
                self.assertIs(receipt[field], False)


if __name__ == "__main__":
    unittest.main()
