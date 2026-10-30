"""Real original-loopback HTML export and private-safe presentation checks."""
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from lightup import lab_score_calibration as cal
from lightup.lab_score_history_html import render_history_html


class HistoryHtmlTests(unittest.TestCase):
    def test_original_history_html_is_offline_and_accessible(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base) / str(i) for i in range(3)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            output = io.StringIO()
            with redirect_stdout(output):
                status = cal.main(["--compare-history", *map(str, roots),
                                   "--format", "html"])
            html = output.getvalue()
            self.assertEqual(status, 0)
            self.assertTrue(html.startswith("<!doctype html>"))
            self.assertIn("<caption>Original synthetic calibration comparisons</caption>", html)
            self.assertIn("<strong>Overall: PASS</strong>", html)
            self.assertIn("3 verified archives, 3 original archive pairs", html)
            self.assertIn("Content-Security-Policy", html)
            self.assertIn("connect-src 'none'", html)
            self.assertNotIn("<script", html)
            self.assertNotIn("http://", html)
            self.assertNotIn("https://", html)
            self.assertNotIn(base, html)
            self.assertNotIn("record_sha256", html)

    def test_nonadjacent_replay_is_a_linked_hold_not_source_disclosure(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base) / str(i) for i in range(3)]
            for root in roots[:2]:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            shutil.copytree(roots[0], roots[2])
            output = io.StringIO()
            with redirect_stdout(output):
                status = cal.main(["--compare-history", *map(str, roots),
                                   "--format", "html"])
            html = output.getvalue()
            self.assertEqual(status, 2)
            self.assertIn("<strong>Overall: HOLD</strong>", html)
            self.assertIn("href='#pair-1-3'", html)
            self.assertIn("Original evidence reused", html)
            self.assertIn("Archive 1 versus 3: HOLD", html)
            self.assertNotIn(base, html)
            self.assertNotIn("sha256", html)

    def test_rejects_invalid_source_without_writing_partial_html(self):
        with tempfile.TemporaryDirectory() as base:
            roots = [Path(base) / str(i) for i in range(2)]
            for root in roots:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            (roots[1] / "report.json").write_bytes(b"corrupted")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--compare-history", *map(str, roots),
                                   "--format", "html"])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("archive 2 not verified", err.getvalue())
            self.assertNotIn(base, err.getvalue())

    def test_untrusted_metric_content_is_never_rendered_as_html(self):
        report = {
            "schema": cal.HISTORY_SCHEMA,
            "archives_checked": 2,
            "passed": False,
            "pairs": [{"previous_index": 1, "current_index": 2, "passed": False}],
            "pairwise_holds": [{
                "previous_index": 1, "current_index": 2,
                "independent_evaluations": True, "score_stable": False,
                "metric_deltas": [
                    {"capability": "http_baseline", "metric": "coverage_assessed",
                     "previous": "<img src=x onerror=alert(1)>", "current": 2},
                    {"capability": "PRIVATE", "metric": "SECRET",
                     "previous": "private", "current": 22},
                ],
            }],
        }
        html = render_history_html(report)
        self.assertIn("http_baseline / coverage_assessed", html)
        self.assertIn("unknown → 2", html)
        self.assertNotIn("onerror", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("PRIVATE / SECRET", html)
        self.assertNotIn("SECRET", html)
        self.assertNotIn("<script", html)


if __name__ == "__main__":
    unittest.main()
