"""True offline child-process tests for scored scenario cohorts (#1513)."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_assessment_runtime_cli_1513 import case

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/assessment_runtime_ground_truth_cohort_cli_1513.py"


def packet(identity, when):
    document = case(identity, when)
    document["scenario"] = {
        "scenario_id": identity, "name": "fictional " + identity,
        "description": "", "targets": ["127.0.0.1"],
        "endpoints": ["127.0.0.1"],
        "expected_findings": [{
            "identifier": "lab-" + identity, "title": "planted",
            "capability_id": "offline", "severity": "low",
        }],
    }
    return document


class ScoredCohortCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old = [packet("b", "baseline"), packet("a", "baseline")]
        self.new = [packet("a", "next"), packet("b", "next")]

    def run_cli(self, new=None, raw=None):
        root = Path(self.temp.name)
        old_path, new_path = root / "old.json", root / "new.json"
        old_path.write_text(json.dumps(self.old), encoding="utf-8")
        new_path.write_bytes(
            raw if raw is not None else json.dumps(
                self.new if new is None else new
            ).encode("utf-8")
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(old_path), str(new_path)],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )

    def test_real_lab_record_envelopes_sorted_without_authority(self):
        response = self.run_cli()
        self.assertEqual(response.returncode, 2, response.stderr)
        result = json.loads(response.stdout)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual([x["scenario_id"] for x in result["comparisons"]], ["a", "b"])
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(result[key], False)

    def test_single_adverse_metric_forces_nonzero_hold(self):
        candidate = deepcopy(self.new)
        candidate[0]["record"]["metrics"]["policy_violations"] = 1
        response = self.run_cli(new=candidate)
        self.assertEqual(response.returncode, 3, response.stderr)
        self.assertEqual(json.loads(response.stdout)["regressed_scenarios"], ["a"])

    def test_malformed_or_changed_ground_truth_is_atomic_hold(self):
        mutators = (
            lambda x: x[0]["scenario"]["expected_findings"].clear(),
            lambda x: x[0]["scenario"]["targets"].__setitem__(0, "8.8.8.8"),
            lambda x: x[0]["scenario"]["endpoints"].__setitem__(0, "8.8.8.8"),
            lambda x: x.pop(),
            lambda x: x.append(deepcopy(x[0])),
        )
        for mutate in mutators:
            modified = deepcopy(self.new)
            mutate(modified)
            response = self.run_cli(new=modified)
            data = json.loads(response.stdout)
            self.assertEqual((response.returncode, data["status"], data["comparisons"]),
                             (3, "HOLD", []))
            self.assertEqual(response.stderr, "")

    def test_bad_bytes_duplicate_keys_deep_input_no_echo(self):
        payloads = (
            b'{"secret":"PRIVATE SCENARIO"}',
            b"[" * 1200 + b"0" + b"]" * 1200,
            b"Q" * 262145,
            b'[{"scenario":{},"scenario":{}}]',
        )
        for payload in payloads:
            response = self.run_cli(raw=payload)
            self.assertEqual(response.returncode, 3)
            self.assertEqual(json.loads(response.stdout)["comparisons"], [])
            self.assertNotIn("PRIVATE SCENARIO", response.stdout)
            self.assertEqual(response.stderr, "")

    def test_no_args_never_succeeds(self):
        response = subprocess.run([sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(response.returncode, 3)
        self.assertEqual(json.loads(response.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
