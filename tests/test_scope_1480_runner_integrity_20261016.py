"""#1480: non-authorizing acceptance-runner contract verification."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
RUNNER = ROOT / "scripts" / "check_scope_1480_source_acceptance_20261016.py"


def _runner():
    spec = importlib.util.spec_from_file_location("scope1480_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load owned runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Scope1480RunnerTests(unittest.TestCase):
    def test_original_source_fingerprint_is_exact_main(self):
        reviewer = _runner()
        self.assertTrue(reviewer._original_source_is_pinned())

    def test_drifted_source_fingerprint_forces_hold_without_any_tests(self):
        reviewer = _runner()
        with patch.object(reviewer, "ORIGINAL_SOURCE_BLOB", "0" * 40):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(verdict["status"], "HOLD")
        self.assertEqual(verdict["tests_run"], 0)
        self.assertFalse(verdict["release_authorized"])

    def test_review_test_and_pure_source_blobs_are_pinned(self):
        reviewer = _runner()
        self.assertTrue(reviewer._original_source_is_pinned())
        self.assertTrue(reviewer._review_material_is_pinned())
        self.assertEqual(len(reviewer.PINNED_REVIEW_BLOBS), 5)

    def test_substituted_test_blob_holds_before_running_any_test(self):
        reviewer = _runner()
        swapped = dict(reviewer.PINNED_REVIEW_BLOBS)
        victim = sorted(swapped)[0]
        swapped[victim] = "0" * 40
        out = io.StringIO()
        with patch.object(reviewer, "PINNED_REVIEW_BLOBS", swapped), patch.object(
            reviewer.unittest.TextTestRunner, "run",
            side_effect=AssertionError("tampered evidence must not execute"),
        ):
            with contextlib.redirect_stdout(out):
                code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(verdict["reason"], "review_material_blob_mismatch")
        self.assertEqual(verdict["tests_run"], 0)
        self.assertEqual(verdict["status"], "HOLD")
        self.assertFalse(verdict["may_issue_grants"])
        self.assertFalse(verdict["release_authorized"])

    def test_original_scope_and_grant_dependencies_are_byte_pinned(self):
        reviewer = _runner()
        self.assertEqual(set(reviewer.ORIGINAL_DEPENDENCY_BLOBS), {
            "src/lightup/models.py",
            "src/lightup/scope.py",
        })
        self.assertTrue(reviewer._original_dependency_sources_are_pinned())
        self.assertTrue(reviewer._review_blobs_match(
            reviewer.ORIGINAL_DEPENDENCY_BLOBS
        ))

    def test_drifted_original_dependency_forces_early_hold_without_running_tests(self):
        for source in ("src/lightup/models.py", "src/lightup/scope.py"):
            with self.subTest(source=source):
                reviewer = _runner()
                changed = dict(reviewer.ORIGINAL_DEPENDENCY_BLOBS)
                changed[source] = "0" * 40
                out = io.StringIO()
                with patch.object(reviewer, "ORIGINAL_DEPENDENCY_BLOBS", changed), patch.object(
                    reviewer.unittest.TextTestRunner, "run",
                    side_effect=AssertionError("drifted original dependencies must not run"),
                ):
                    with contextlib.redirect_stdout(out):
                        code = reviewer.main()
                verdict = json.loads(out.getvalue())
                self.assertEqual(code, 1)
                self.assertEqual(verdict["status"], "HOLD")
                self.assertEqual(verdict["reason"], "original_authorization_dependency_blob_mismatch")
                self.assertEqual(verdict["tests_run"], 0)
                self.assertFalse(verdict["consent_verified"])
                self.assertFalse(verdict["release_authorized"])

    def test_missing_original_dependency_path_holds_before_test_execution(self):
        reviewer = _runner()
        changed = dict(reviewer.ORIGINAL_DEPENDENCY_BLOBS)
        changed["src/lightup/models.py"] = "0" * 40
        missing = ROOT / "src" / "lightup" / "does_not_exist_1480.py"
        changed[str(missing.relative_to(ROOT))] = changed.pop("src/lightup/models.py")
        out = io.StringIO()
        with patch.object(reviewer, "ORIGINAL_DEPENDENCY_BLOBS", changed), patch.object(
            reviewer.unittest.TextTestRunner, "run",
            side_effect=AssertionError("missing source must not run"),
        ):
            with contextlib.redirect_stdout(out):
                code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(verdict["reason"], "original_authorization_dependency_blob_mismatch")
        self.assertEqual(verdict["tests_run"], 0)
        self.assertFalse(verdict["may_dispatch_tools"])

    def test_machine_readable_case_digest_is_deterministic_sorted_lf(self):
        reviewer = _runner()
        expected = hashlib.sha256(
            "\n".join(sorted(reviewer.EXPECTED_TEST_IDS)).encode("utf-8")
        ).hexdigest()
        self.assertEqual(reviewer._expected_case_manifest_sha256(), expected)
        self.assertEqual(len(expected), 64)

    def test_self_reported_evidence_explicitly_denies_ci_and_release_status(self):
        reviewer = _runner()
        payload = reviewer._verdict(
            "REVIEW_ONLY", "original_source_gap_reproduced", 44, 1
        )
        self.assertEqual(payload["evidence_manifest_version"], 1)
        self.assertIs(payload["evidence_self_reported"], True)
        self.assertIs(payload["independent_ci_attestation"], False)
        self.assertEqual(payload["original_activation_git_blob"], reviewer.ORIGINAL_SOURCE_BLOB)
        self.assertEqual(payload["original_dependency_git_blobs"], reviewer.ORIGINAL_DEPENDENCY_BLOBS)
        self.assertEqual(payload["reviewed_local_git_blobs"], reviewer.PINNED_REVIEW_BLOBS)
        self.assertEqual(payload["expected_case_count"], 44)
        self.assertEqual(payload["expected_case_manifest_sha256"], reviewer._expected_case_manifest_sha256())
        for field in (
            "source_fixed", "full_suite_green", "permanent_vps_proven",
            "consent_verified", "revocation_verified", "may_issue_grants",
            "may_dispatch_tools", "may_scan_targets", "may_merge",
            "may_deploy", "release_authorized",
        ):
            with self.subTest(field=field):
                self.assertIs(payload[field], False)

    def test_failed_source_pin_keeps_its_read_only_audit_manifest(self):
        reviewer = _runner()
        with patch.object(reviewer, "ORIGINAL_SOURCE_BLOB", "0" * 40):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = reviewer.main()
        payload = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "HOLD")
        self.assertEqual(payload["tests_run"], 0)
        self.assertIs(payload["independent_ci_attestation"], False)
        self.assertEqual(payload["original_activation_git_blob"], "0" * 40)
        self.assertEqual(len(payload["expected_case_manifest_sha256"]), 64)
        self.assertFalse(payload["release_authorized"])

    def _assert_drift_after_test_execution_holds(self, pinned_check_name):
        reviewer = _runner()
        output = io.StringIO()
        # No checkout mutation is needed: this is a deterministic
        # simulated source replacement between preflight and postflight.
        with patch.object(
            reviewer, pinned_check_name, side_effect=[True, False],
        ) as check:
            with contextlib.redirect_stdout(output):
                exit_code = reviewer.main()
        verdict = json.loads(output.getvalue())
        self.assertEqual(check.call_count, 2)
        self.assertEqual(exit_code, 1)
        self.assertEqual(verdict["status"], "HOLD")
        self.assertEqual(verdict["reason"], "source_or_review_drift_during_tests")
        self.assertEqual(verdict["tests_run"], 44)
        self.assertEqual(verdict["expected_source_reds"], 1)
        self.assertIs(verdict["independent_ci_attestation"], False)
        self.assertIs(verdict["release_authorized"], False)
        self.assertIs(verdict["may_issue_grants"], False)
        self.assertIs(verdict["may_dispatch_tools"], False)
        self.assertIs(verdict["full_suite_green"], False)

    def test_original_activation_blob_drift_after_run_is_hold(self):
        self._assert_drift_after_test_execution_holds("_original_source_is_pinned")

    def test_original_dependency_blob_drift_after_run_is_hold(self):
        self._assert_drift_after_test_execution_holds(
            "_original_dependency_sources_are_pinned"
        )

    def test_review_source_blob_drift_after_run_is_hold(self):
        self._assert_drift_after_test_execution_holds("_review_material_is_pinned")

    def test_loaded_method_ids_match_exact_source_inventory(self):
        reviewer = _runner()
        suite = unittest.TestSuite()
        for filename in reviewer.OWN_TEST_FILES:
            suite.addTests(unittest.defaultTestLoader.discover(
                start_dir=str(ROOT / "tests"), pattern=filename,
            ))
        ids = reviewer._loaded_test_ids(suite)
        self.assertEqual(len(ids), 44)
        self.assertEqual(len(set(ids)), 44)
        self.assertTrue(reviewer._has_exact_test_inventory(ids))

    def test_same_count_wrong_or_duplicated_case_ids_are_denied(self):
        reviewer = _runner()
        ids = tuple(sorted(reviewer.EXPECTED_TEST_IDS))
        self.assertTrue(reviewer._has_exact_test_inventory(ids))
        substituted = (*ids[:-1], "test_lookalike.WrongCase.test_false_green")
        duplicate = (*ids[:-1], ids[0])
        for sample in (substituted, duplicate, ids[:-1], (*ids, ids[0])):
            with self.subTest(sample_count=len(sample)):
                self.assertFalse(reviewer._has_exact_test_inventory(sample))

    def test_manifest_drift_holds_before_any_unit_test_runs(self):
        reviewer = _runner()
        changed = set(reviewer.EXPECTED_TEST_IDS)
        changed.pop()
        changed.add("test_substituted.Untrusted.test_success")
        out = io.StringIO()
        with patch.object(reviewer, "EXPECTED_TEST_IDS", frozenset(changed)), patch.object(
            reviewer.unittest.TextTestRunner, "run",
            side_effect=AssertionError("a mismatched suite must never execute"),
        ):
            with contextlib.redirect_stdout(out):
                code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(verdict["status"], "HOLD")
        self.assertEqual(verdict["reason"], "test_inventory_mismatch")
        self.assertEqual(verdict["tests_run"], 0)
        self.assertFalse(verdict["may_dispatch_tools"])
        self.assertFalse(verdict["release_authorized"])

    def test_source_pinned_full_44_method_oracle_never_authorizes(self):
        reviewer = _runner()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(verdict["status"], "REVIEW_ONLY")
        self.assertEqual(verdict["tests_run"], 44)
        self.assertEqual(verdict["expected_source_reds"], 1)
        for key in (
            "source_fixed",
            "full_suite_green",
            "permanent_vps_proven",
            "consent_verified",
            "revocation_verified",
            "may_issue_grants",
            "may_dispatch_tools",
            "may_scan_targets",
            "may_merge",
            "may_deploy",
            "release_authorized",
        ):
            with self.subTest(key=key):
                self.assertIs(verdict[key], False)


if __name__ == "__main__":
    unittest.main()
