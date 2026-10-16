"""#1480: non-authorizing acceptance-runner contract verification."""

from __future__ import annotations

import contextlib
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

    def test_loaded_method_ids_match_exact_source_inventory(self):
        reviewer = _runner()
        suite = unittest.TestSuite()
        for filename in reviewer.OWN_TEST_FILES:
            suite.addTests(unittest.defaultTestLoader.discover(
                start_dir=str(ROOT / "tests"), pattern=filename,
            ))
        ids = reviewer._loaded_test_ids(suite)
        self.assertEqual(len(ids), 36)
        self.assertEqual(len(set(ids)), 36)
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

    def test_source_pinned_full_36_method_oracle_never_authorizes(self):
        reviewer = _runner()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(verdict["status"], "REVIEW_ONLY")
        self.assertEqual(verdict["tests_run"], 36)
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
