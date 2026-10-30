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

    def test_canonical_offline_browser_navigates_all_archives_without_scripts(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(4)]
            for root in roots[:3]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[3])
            code, html, err = invoke(roots)
            self.assertEqual((code, err), (2, ""))
            self.assertIn("Overall: HOLD", html)
            self.assertIn("Browse original archives", html)
            self.assertIn("role='region' tabindex='0'", html)
            for archive in range(1, 5):
                self.assertIn(f"href='#archive-{archive}'", html)
                self.assertIn(f"<details id='archive-{archive}'>", html)
                self.assertIn(f"Comparisons involving archive {archive}", html)
            self.assertIn("Archive 3: 0 HOLD of 3 comparisons", html)
            self.assertIn("Archive 4: 1 HOLD of 3 comparisons", html)
            self.assertIn("href='#pair-1-4'>Read HOLD details", html)
            self.assertIn("href='#pair-1-4' aria-label=", html)
            self.assertEqual(html.count("<details id='archive-"), 4)
            self.assertIn("Original archive comparison matrix", html)
            for forbidden in (base, "sha256", "<script", "http://", "https://"):
                self.assertNotIn(forbidden, html)

    def test_canonical_saved_browser_reverifies_private_bundle_read_only(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            dest = Path(base)/"review"
            self.assertEqual(invoke(roots, saved=dest, create=True), (0, "", ""))
            original = {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes())
                        for p in dest.iterdir()}
            code, text, err = invoke(roots, saved=dest)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("VERIFIED; original comparison PASS", text)
            self.assertEqual(original,
                             {p.name:(p.stat().st_ino,p.stat().st_mtime_ns,p.read_bytes())
                              for p in dest.iterdir()})
            saved_html = (dest/"history.html").read_text()
            self.assertIn("Browse original archives", saved_html)
            (dest/"history.html").write_text("altered")
            code, text, err = invoke(roots, saved=dest)
            self.assertEqual((code, text), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_archive_queue_has_links_to_every_original_hold(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base)/str(i) for i in range(4)]
            for root in roots[:2]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[2])
            shutil.copytree(roots[0], roots[3])
            code, html, err = invoke(roots)
            self.assertEqual((code, err), (2, ""))
            self.assertIn("First HOLD pair 1 versus 3</a>, "
                          "<a href='#pair-1-4'>Also 1 versus 4", html)
            self.assertIn("First HOLD pair 1 versus 3</a>, "
                          "<a href='#pair-3-4'>Also 3 versus 4", html)
            self.assertIn("Archive 1: 2 HOLD of 3 comparisons", html)
            self.assertIn("Archive 3: 2 HOLD of 3 comparisons", html)
            self.assertIn("Overall: HOLD", html)
            self.assertNotIn(base, html)

    def test_scorer_hotspot_has_links_to_all_changed_pairs(self):
        from lightup.lab_score_history_html import render_history_html
        pairs = [
            {"previous_index":1, "current_index":2, "passed":True,
             "independent_evaluations":True, "score_stable":True},
            {"previous_index":1, "current_index":3, "passed":False,
             "independent_evaluations":True, "score_stable":False},
            {"previous_index":2, "current_index":3, "passed":False,
             "independent_evaluations":True, "score_stable":False},
        ]
        holds = [{
            "previous_index":i, "current_index":3, "independent_evaluations":True,
            "score_stable":False,
            "metric_deltas":[{"capability":"http_baseline",
                              "metric":"coverage_assessed", "previous":i, "current":3}]
        } for i in (1,2)]
        report = {"schema":cal.HISTORY_SCHEMA, "archives_checked":3,
                  "pairs_checked":3, "pairs":pairs, "pairwise_holds":holds,
                  "passed":False, "independent_evaluations":True, "score_stable":False}
        html = render_history_html(report)
        self.assertIn("<td>2</td><td>coverage_assessed</td>"
                      "<td><a href='#pair-1-3'>Review 1 versus 3</a>, "
                      "<a href='#pair-2-3'>Review 2 versus 3</a></td>", html)
        self.assertIn("First HOLD pair 1 versus 3</a>, "
                      "<a href='#pair-2-3'>Also 2 versus 3</a>", html)
        self.assertNotIn("<script", html)
