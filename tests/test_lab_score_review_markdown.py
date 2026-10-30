"""Original synthetic archive human handoff, without source disclosure."""
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from lightup import lab_score_calibration as cal
from lightup.lab_score_history_html import render_history_markdown

class ReviewMarkdownTests(unittest.TestCase):
    def invoke(self, roots):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = cal.main(["--compare-history", *map(str, roots), "--format", "review-markdown"])
        return status, out.getvalue(), err.getvalue()

    def test_verified_three_archive_workflow_and_source_safety(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(3)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            code, brief, err = self.invoke(roots)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("synthetic lab history — PASS", brief)
            self.assertIn("3 verified local archives; 3 original pairs", brief)
            self.assertIn("| 1–3 | PASS | yes | yes |", brief)
            self.assertIn("No archive requires review.", brief)
            self.assertIn("No external targets, scans", brief)
            for word in (base, "sha256", "receipt", "report.json", "http://"):
                self.assertNotIn(word, brief)

    def test_replay_hold_and_corrupt_original_never_leaks(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(3)]
            for root in roots[:2]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[2])
            code, brief, err = self.invoke(roots)
            self.assertEqual((code, err), (2, ""))
            self.assertIn("synthetic lab history — HOLD", brief)
            self.assertIn("| 1–3 | HOLD | no | yes |", brief)
            self.assertIn("| 1 | 1 | 1 | 0 |", brief)
            self.assertEqual(brief, render_history_markdown(cal.compare_saved_calibration_history(roots)))
            self.assertNotIn(base, brief)
            (roots[0]/"report.json").write_bytes(b"corrupt")
            code, brief, err = self.invoke(roots)
            self.assertEqual((code, brief), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_invalid_report_refused_before_any_render(self):
        with self.assertRaises(ValueError):
            render_history_markdown({"schema": cal.HISTORY_SCHEMA, "archives_checked": 2, "pairs": []})
