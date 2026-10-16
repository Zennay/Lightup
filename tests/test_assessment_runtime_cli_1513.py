"""True subprocess regression suite for opt-in assessment JSON CLI (#1513)."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lightup.ai.orchestration import RunContext
from lightup.labeval import LabScenario, LabEvaluationHarness, EvaluationMetrics

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assessment_runtime_compare_cli_1513.py"


def case(scenario_id, version, valid=3):
    scenario = LabScenario(scenario_id, "lab only", targets=("127.0.0.1",))
    harness = LabEvaluationHarness(engine_version=version)
    context = harness.start_run(scenario)
    record = harness.record(
        scenario, context,
        EvaluationMetrics(valid_findings=valid, coverage_assessed=2,
                          evidence_quality=0.8, runtime_seconds=1.2),
    )
    return {
        "record": record.to_dict(),
        "context": {
            "run_id": context.run_id, "client_id": context.client_id,
            "engagement_id": context.engagement_id,
            "mode": context.mode.value, "approved_risk": int(context.approved_risk),
            "authorization": None, "is_lab": True,
            "created_at": context.created_at.isoformat(),
        },
    }


class OfflineCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.baseline = case("one", "old")
        self.candidate = case("one", "new")

    def run_cases(self, baseline=None, candidate=None, raw_baseline=None, raw_candidate=None):
        f1, f2 = self.base / "before.json", self.base / "after.json"
        f1.write_bytes(raw_baseline if raw_baseline is not None else
                       json.dumps(baseline if baseline is not None else self.baseline).encode())
        f2.write_bytes(raw_candidate if raw_candidate is not None else
                       json.dumps(candidate if candidate is not None else self.candidate).encode())
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(f1), str(f2)],
            text=True, capture_output=True, env=env, timeout=15,
        )

    def test_actual_exported_harness_records_compare(self):
        p = self.run_cases()
        self.assertEqual(p.returncode, 2, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        self.assertEqual(len(data["changes"]), 15)
        for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(data[name], False)

    def test_real_exported_regression_is_nonzero_hold(self):
        self.candidate["record"]["metrics"]["valid_findings"] = 2
        self.candidate["record"]["metrics"]["false_positive_rate"] = 0.0
        p = self.run_cases()
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertEqual(json.loads(p.stdout)["regressions"], ["valid_findings"])

    def test_duplicate_key_nonfinite_and_trailing_input_generic_hold(self):
        original = json.dumps(self.candidate).encode()
        for raw in (
            original.replace(b'"record":', b'"record":null,"record":', 1),
            original.replace(b'"evidence_quality": 0.8', b'"evidence_quality": NaN', 1),
            original + b'  {}',
            b'{"junk": "sensitive name"}',
            original + b"x" * 70_000,
            b'\xff\xfe',
        ):
            with self.subTest(size=len(raw)):
                p = self.run_cases(raw_candidate=raw)
                self.assertEqual(p.returncode, 3)
                self.assertEqual(json.loads(p.stdout), {
                    "status": "HOLD", "authorized": False, "consent_verified": False,
                    "dispatch_allowed": False, "release_allowed": False,
                    "regressions": [], "changes": [],
                })
                self.assertNotIn("sensitive name", p.stdout)

    def test_nonlab_forged_and_mismatched_scenario_hold(self):
        for change in (
            ("context", "is_lab", False),
            ("context", "approved_risk", 1),
            ("context", "client_id", "another-client"),
            ("record", "scenario_id", "other"),
        ):
            candidate = json.loads(json.dumps(self.candidate))
            candidate[change[0]][change[1]] = change[2]
            p = self.run_cases(candidate=candidate)
            self.assertEqual(p.returncode, 3)
            self.assertFalse(json.loads(p.stdout)["release_allowed"])

    def test_nested_json_and_lying_derived_rate_cannot_crash_or_leak(self):
        suspicious = json.loads(json.dumps(self.candidate))
        suspicious["record"]["metrics"]["false_positive_rate"] = 0.75
        raw_inputs = (
            b"[" * 1500 + b"0" + b"]" * 1500,
            json.dumps(suspicious).encode(),
        )
        for raw in raw_inputs:
            p = self.run_cases(raw_candidate=raw)
            self.assertEqual(p.returncode, 3)
            self.assertEqual(json.loads(p.stdout)["status"], "HOLD")
            self.assertEqual(p.stderr, "")
            self.assertFalse(json.loads(p.stdout)["authorized"])

    def test_no_args_never_exit_zero(self):
        p = subprocess.run([sys.executable, str(SCRIPT)],
                           text=True, capture_output=True,
                           env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                           timeout=15)
        self.assertEqual(p.returncode, 3)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
