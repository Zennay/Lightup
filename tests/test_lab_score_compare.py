"""Focused verification of private saved fixed-loopback score comparison."""
from __future__ import annotations
import json
import io
from contextlib import redirect_stdout
import os
import stat
import shutil
import tempfile
import unittest
from pathlib import Path
from lightup.lab_score_compare import compare_score_runs, main, render_score_review
from lightup.lab_score_inspect import inspect_score_run
from lightup.lab_score_suite import run_lab_score_suite

class SavedLabScoreCompareTests(unittest.TestCase):
    def test_two_independent_real_loopback_runs_remain_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary)/"baseline", Path(temporary)/"candidate"
            self.assertTrue(run_lab_score_suite(a)["passed"])
            self.assertTrue(run_lab_score_suite(b)["passed"])
            public_inspection=inspect_score_run(a)
            self.assertEqual(
                set(public_inspection["capabilities"]["tls_baseline"]),
                {"record_sha256", "evidence_count"},
            )
            result=compare_score_runs(a,b)
            self.assertTrue(result["passed"],result)
            self.assertTrue(result["independent_evaluations"])
            self.assertTrue(result["score_stable"])
            self.assertEqual(len(result["capabilities"]),3)
            self.assertFalse(result["authorization_granted"])

    def test_real_text_operator_cli_and_unchanged_json(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp)/"PRIVATE-baseline", Path(temp)/"PRIVATE-candidate"
            self.assertTrue(run_lab_score_suite(a)["passed"])
            self.assertTrue(run_lab_score_suite(b)["passed"])
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--baseline-dir", str(a), "--candidate-dir", str(b),
                             "--format", "text"])
            text = output.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("score comparison: PASS", text)
            self.assertIn("service_inventory: PASS", text)
            self.assertIn("tls_baseline: PASS", text)
            self.assertIn("http_baseline: PASS", text)
            self.assertIn("Authority: none", text)
            self.assertNotIn(temp, text)
            self.assertNotIn("PRIVATE-", text)
            self.assertNotIn("record_sha256", text)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--baseline-dir", str(a), "--candidate-dir", str(b)])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output.getvalue())["passed"])
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--baseline-dir", str(a), "--candidate-dir", str(a),
                             "--format", "text"])
            self.assertEqual(code, 2)
            self.assertEqual(output.getvalue(), "")

    def test_text_review_safely_shows_drift_and_reused_evaluations(self):
        report = {
            "passed": False, "score_stable": False,
            "independent_evaluations": False,
            "capabilities": {
                name: {
                    "distinct_evaluation": name != "service_inventory",
                    "baseline_evidence_count": 2,
                    "candidate_evidence_count": 2,
                    "changed_metrics": (
                        {"valid_findings": {"baseline": 1, "candidate": 0}}
                        if name == "tls_baseline" else {}
                    ),
                } for name in ("service_inventory", "tls_baseline", "http_baseline")
            },
        }
        text = render_score_review(report)
        self.assertIn("comparison: HOLD", text)
        self.assertIn("Evaluations: reused; calibration: changed", text)
        self.assertIn("service_inventory: HOLD", text)
        self.assertIn("tls_baseline: HOLD", text)
        self.assertIn("valid_findings: 1 -> 0", text)
        self.assertIn("http_baseline: PASS", text)
        self.assertNotIn("record_sha256", text)

    def test_host_umask_keeps_persisted_evidence_owner_private(self):
        # Reproduce the 0022 CI runner before the producer creates SQLite.
        with tempfile.TemporaryDirectory() as temporary:
            previous = os.umask(0o022)
            try:
                output = Path(temporary) / "ci-style"
                report = run_lab_score_suite(output)
            finally:
                os.umask(previous)
            self.assertTrue(report["passed"], report)
            for capability in ("service_inventory", "tls_baseline", "http_baseline"):
                self.assertEqual(stat.S_IMODE(
                    (output / f"{capability}.sqlite3").stat().st_mode), 0o600)
            self.assertTrue(inspect_score_run(output)["passed"])

    def test_reused_bundle_not_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            a,b=Path(temporary)/"baseline",Path(temporary)/"copy"
            self.assertTrue(run_lab_score_suite(a)["passed"])
            shutil.copytree(a,b)
            result=compare_score_runs(a,b)
            self.assertFalse(result["passed"])
            self.assertFalse(result["independent_evaluations"])
            with self.assertRaises(ValueError):
                compare_score_runs(a,a)

    def test_corrupted_saved_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            a,b=Path(temporary)/"baseline",Path(temporary)/"copy"
            self.assertTrue(run_lab_score_suite(a)["passed"])
            shutil.copytree(a,b)
            target=b/"report.json"
            content=json.loads(target.read_text())
            content["scorers"]["tls_baseline"]["metrics"]["valid_findings"]=999
            target.write_text(json.dumps(content,indent=2,sort_keys=True)+"\n")
            with self.assertRaises(ValueError):
                compare_score_runs(a,b)
            self.assertEqual(main(["--baseline-dir",str(a),"--candidate-dir",str(b)]),2)

if __name__=="__main__":
    unittest.main()
