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

    def test_source_pinned_full_33_method_oracle_never_authorizes(self):
        reviewer = _runner()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = reviewer.main()
        verdict = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(verdict["status"], "REVIEW_ONLY")
        self.assertEqual(verdict["tests_run"], 33)
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
