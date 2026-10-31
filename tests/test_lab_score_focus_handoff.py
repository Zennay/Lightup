"""Original offline archive focus must preserve global HOLD and source custody."""
import csv
import gc
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from lightup import lab_score_calibration as cal


def invoke(roots, fmt, focus=3, saved=None):
    args = ["--compare-history", *map(str, roots), "--format", fmt,
            "--focus-archive-index", str(focus)]
    if saved is not None:
        args += ["--verify-html-output-dir", str(saved)]
    # Older, unrelated SQLite/TemporaryDirectory tests may finalize during the
    # CLI's stderr capture. Collect them first so only this invocation's
    # diagnostics are judged, never spurious prior-test ResourceWarnings.
    gc.collect()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = cal.main(args)
    return status, out.getvalue(), err.getvalue()


class FocusArchiveTests(unittest.TestCase):
    def test_source_free_subset_cannot_hide_global_hold(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(4)]
            for root in roots[:3]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[3])
            for fmt in ("review-json", "review-csv", "review-markdown"):
                code, out, err = invoke(roots, fmt)
                self.assertEqual((code, err), (2, ""))
                self.assertNotIn(base, out)
                self.assertNotIn("sha256", out)
                if fmt == "review-json":
                    data = json.loads(out)
                    self.assertFalse(data["passed"])
                    self.assertEqual(data["pairs_checked"], 6)
                    self.assertEqual(data["review_focus"]["pairs_checked"], 3)
                    self.assertEqual(data["review_focus"]["hold_pairs"], 0)
                    self.assertEqual(data["review_focus"]["global_hold_pairs"], 1)
                elif fmt == "review-csv":
                    rows = list(csv.DictReader(io.StringIO(out)))
                    self.assertEqual(len(rows), 3)
                    self.assertTrue(all(x["status"] == "PASS"
                                        and x["global_status"] == "HOLD"
                                        and x["global_hold_pairs"] == "1" for x in rows))
                else:
                    self.assertIn("history — HOLD", out)
                    self.assertIn("Focused archive 3: 3 pairs; 0 HOLD", out)
                    self.assertIn("Global HOLD count remains 1", out)
                    self.assertNotIn("| 1–4 |", out)

    def test_focused_saved_review_is_source_verified_before_export(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            saved = Path(base)/"private-review"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cal.main(["--compare-history", *map(str, roots),
                                 "--format", "html", "--html-output-dir", str(saved)])
            self.assertEqual(code, 0)
            before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns,
                               p.read_bytes()) for p in saved.iterdir()}
            for fmt in ("review-json", "review-csv", "review-markdown"):
                code, output, err = invoke(roots, fmt, 1, saved)
                self.assertEqual((code, err), (0, ""))
                self.assertTrue(output)
            after = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns,
                              p.read_bytes()) for p in saved.iterdir()}
            self.assertEqual(before, after)
            (saved/"review_summary.json").write_bytes(b"tampered")
            for fmt in ("review-json", "review-csv", "review-markdown"):
                code, output, err = invoke(roots, fmt, 1, saved)
                self.assertEqual((code, output), (2, ""))
                self.assertNotIn(base, err)
                self.assertTrue(err)
