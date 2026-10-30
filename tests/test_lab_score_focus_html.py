"""Offline focus HTML must preserve global HOLD and saved-source custody."""
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from lightup import lab_score_calibration as cal


def invoke(roots, focus=None, saved=None, create=False):
    args = ["--compare-history", *map(str, roots), "--format", "html"]
    if focus is not None:
        args += ["--focus-archive-index", str(focus)]
    if saved is not None:
        args += ["--html-output-dir" if create else "--verify-html-output-dir", str(saved)]
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cal.main(args)
    return code, out.getvalue(), err.getvalue()


class FocusedHtmlTests(unittest.TestCase):
    def test_nonadjacent_hold_remains_visible_outside_focus(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(4)]
            for root in roots[:3]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[3])
            code, html, err = invoke(roots, 3)
            self.assertEqual((code, err), (2, ""))
            for text in ("<strong>Overall: HOLD</strong>",
                         "Focused archive 3", "3 original pairs; 0 focused HOLD; 1 global HOLD",
                         "The global result remains HOLD", "Original archive comparison matrix",
                         "href='#pair-1-4'", "Content-Security-Policy"):
                self.assertIn(text, html)
            for forbidden in (base, "sha256", "<script", "http://"):
                self.assertNotIn(forbidden, html)
            self.assertEqual(html.count("<caption>Anonymous comparisons involving archive 3"), 1)

    def test_saved_review_is_verified_read_only_before_focused_stdout(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            saved = Path(base)/"private-review"
            self.assertEqual(invoke(roots, saved=saved, create=True), (0, "", ""))
            before = {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes())
                      for p in saved.iterdir()}
            code, html, err = invoke(roots, 1, saved)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("Focused archive 1", html)
            after = {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes())
                     for p in saved.iterdir()}
            self.assertEqual(before, after)
            (saved/"source_receipt.json").write_bytes(b"tampered")
            code, html, err = invoke(roots, 1, saved)
            self.assertEqual((code, html), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_invalid_focus_never_emits_partial_html(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            for index in (0, -1, 3):
                code, html, err = invoke(roots, index)
                self.assertEqual((code, html), (2, ""))
                self.assertIn("HOLD", err)
