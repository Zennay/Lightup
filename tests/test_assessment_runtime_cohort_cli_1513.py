"""Actual subprocess tests for offline atomic cohort CLI (#1513)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_assessment_runtime_cli_1513 import case

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assessment_runtime_compare_cohort_cli_1513.py"


class CohortCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.before = [case("a", "before"), case("b", "before")]
        self.after = [case("b", "after"), case("a", "after")]

    def run_comparison(self, before=None, after=None, raw_after=None):
        old, new = self.base / "baseline.json", self.base / "candidate.json"
        old.write_text(json.dumps(self.before if before is None else before), encoding="utf-8")
        new.write_bytes(raw_after if raw_after is not None
                        else json.dumps(self.after if after is None else after).encode())
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(old), str(new)],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )

    def test_real_harness_json_array_sorted_and_non_authorizing(self):
        p = self.run_comparison()
        self.assertEqual(p.returncode, 2, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        self.assertEqual([x["scenario_id"] for x in data["comparisons"]], ["a", "b"])
        self.assertEqual(len(data["comparisons"][0]["changes"]), 15)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(data[key], False)

    def test_regression_in_one_scenario_holds_all(self):
        after = json.loads(json.dumps(self.after))
        after[0]["record"]["metrics"]["valid_findings"] = 2
        # invalid findings remain 0, so the derived rate remains 0.
        p = self.run_comparison(after=after)
        self.assertEqual(p.returncode, 3)
        data = json.loads(p.stdout)
        self.assertEqual(data["regressed_scenarios"], ["b"])
        self.assertFalse(data["release_allowed"])

    def test_duplicate_missing_extra_and_malformed_are_atomic_generic_hold(self):
        cases = (
            self.after[:1], self.after + [case("extra", "new")],
            [self.after[0], self.after[0]], [],
            [case("A", "after"), self.after[0]],
            [case(f"s{i}", "new") for i in range(65)],
        )
        for candidate in cases:
            with self.subTest(length=len(candidate)):
                p = self.run_comparison(after=candidate)
                self.assertEqual(p.returncode, 3)
                self.assertEqual(json.loads(p.stdout)["comparisons"], [])

    def test_malformed_json_no_echo_no_traceback(self):
        for raw in (
            b"[" * 1400 + b"0" + b"]" * 1400,
            b'{"not":"cohort secret"}',
            b"[" + json.dumps(self.after[0]).encode() + b",null]",
            b"x" * 262_145,
        ):
            p = self.run_comparison(raw_after=raw)
            self.assertEqual(p.returncode, 3)
            self.assertEqual(json.loads(p.stdout)["status"], "HOLD")
            self.assertEqual(json.loads(p.stdout)["comparisons"], [])
            self.assertNotIn("cohort secret", p.stdout)
            self.assertEqual(p.stderr, "")

    def test_no_args_cannot_exit_zero(self):
        p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True,
                           text=True, timeout=15,
                           env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(p.returncode, 3)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
