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

class PersistedReviewExportTests(unittest.TestCase):
    """Saved bundle is fully verified before any source-free output."""

    @staticmethod
    def call(roots, fmt, dest, verify=True):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cal.main(["--compare-history", *map(str, roots),
                             "--format", fmt,
                             "--verify-html-output-dir" if verify else "--html-output-dir",
                             str(dest)])
        return code, out.getvalue(), err.getvalue()

    def test_verified_export_is_read_only_and_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            dest = Path(base)/"saved-review"
            self.assertEqual(self.call(roots, "html", dest, False), (0, "", ""))
            before = {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes()) for p in dest.iterdir()}
            for fmt in ("review-json", "review-markdown"):
                code, out, err = self.call(roots, fmt, dest)
                self.assertEqual((code, err), (0, ""))
                self.assertNotIn(base, out)
                self.assertIn("passed" if fmt == "review-json" else "PASS", out)
            after = {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes()) for p in dest.iterdir()}
            self.assertEqual(before, after)
            (dest/"history.html").write_text("tampered HTML")
            for fmt in ("review-json", "review-markdown"):
                code, out, err = self.call(roots, fmt, dest)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("false" if fmt == "review-json" else "HOLD", err)
                self.assertNotIn(base, err)

    def test_altered_original_returns_no_partial_export(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            dest = Path(base)/"saved-review"
            self.assertEqual(self.call(roots, "html", dest, False)[0], 0)
            (roots[0]/"report.json").write_bytes(b"corrupted original")
            for fmt in ("review-json", "review-markdown"):
                code, out, err = self.call(roots, fmt, dest)
                self.assertEqual((code, out), (2, ""))
                self.assertTrue(err)
                self.assertNotIn(base, err)

    def test_saved_source_free_csv_handoff_and_tamper_hold(self):
        import csv
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            dest = Path(base)/"saved-private"
            self.assertEqual(self.call(roots, "html", dest, False), (0, "", ""))
            original = {p.name:p.read_bytes() for p in dest.iterdir()}
            status, output, err = self.call(roots, "review-csv", dest)
            self.assertEqual((status, err), (0, ""))
            records = list(csv.DictReader(io.StringIO(output)))
            self.assertEqual(records, [{
                "previous_index": "1", "current_index": "2", "status": "PASS",
                "independent_evaluations": "True", "score_stable": "True"
            }])
            self.assertEqual(original, {p.name:p.read_bytes() for p in dest.iterdir()})
            for forbidden in (base, "sha256", "receipt", "candidate_value", "http://"):
                self.assertNotIn(forbidden, output)
            (dest/"source_receipt.json").write_bytes(b"altered source binding")
            status, output, err = self.call(roots, "review-csv", dest)
            self.assertEqual((status, output), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_csv_nonadjacent_replay_returns_useful_hold_without_source(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(3)]
            for root in roots[:2]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[2])
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--compare-history", *map(str, roots),
                                   "--format", "review-csv"])
            self.assertEqual((status, err.getvalue()), (2, ""))
            self.assertIn("1,3,HOLD,False,True", out.getvalue())
            self.assertNotIn(base, out.getvalue())
