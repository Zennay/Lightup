"""Source-free, accessible portable HUMAN dashboard: real synthetic CLI workflow."""
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from zipfile import ZipFile

from lightup import lab_score_calibration as calibration


def invoke(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = calibration.main(list(map(str, args)))
    return rc, stdout.getvalue(), stderr.getvalue()


class PortableDashboardTests(unittest.TestCase):
    def build(self, base, sources, name):
        saved, package = base / (name + "-saved"), base / (name + "-portable")
        self.assertIn(invoke("--compare-history", *sources, "--format", "html",
                             "--html-output-dir", saved)[0], (0, 2))
        result = invoke("--compare-history", *sources, "--format", "html",
                        "--verify-html-output-dir", saved,
                        "--portable-review-output-dir", package)
        self.assertEqual(result[2], "")
        path = package / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
        self.assertTrue(path.is_file())
        with ZipFile(path) as z:
            html = z.read("index.html").decode("utf-8")
            history = z.read("history.html").decode("utf-8")
            summary = json.loads(z.read("review.json"))
            manifest = json.loads(z.read("manifest.json"))
            self.assertEqual(manifest["passed"], summary["passed"])
        return result[0], path, html, history, summary

    def test_real_private_pass_dashboard_and_existing_receiver_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = [root / "original1", root / "original2"]
            for source in sources:
                self.assertTrue(calibration.run_lab_score_calibration(source)["passed"])
            rc, portable, html, history, summary = self.build(root, sources, "pass")
            self.assertEqual(rc, 0)
            self.assertIn("Review at a glance", html)
            self.assertIn("Global synthetic result", html)
            self.assertIn("Original comparisons", html)
            self.assertIn("Every original comparison", html)
            self.assertIn("Anonymous archives", html)
            self.assertIn("2</strong><span>Anonymous archives", html)
            self.assertIn("No follow-up", html)
            self.assertIn("source", html.lower())
            self.assertIn("Synthetic PASS only", html)
            self.assertIn("style-src 'unsafe-inline'", html)
            self.assertIn("default-src 'none'", html)
            self.assertIn("href='#content'", html)
            self.assertIn("role='region'", html)
            self.assertIn("href='history.html'", html)
            self.assertNotIn("<script", html)
            self.assertNotIn("http://", html)
            self.assertNotIn(str(root), html)
            self.assertNotIn("source_receipt.json", html)
            self.assertNotIn("source_sha256", html)
            browser_dir = root / "browser"
            self.assertEqual(invoke("--unpack-portable-review", portable,
                                    "--unpack-output-dir", browser_dir)[0], 0)
            self.assertEqual((browser_dir / "index.html").read_text(), html)
            self.assertEqual(invoke("--verify-unpacked-review", portable,
                                    "--unpacked-review-dir", browser_dir)[0], 0)

    def test_nonadjacent_replay_hold_dashboard_global_and_deep_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = [root / str(i) for i in range(4)]
            for source in sources[:3]:
                self.assertTrue(calibration.run_lab_score_calibration(source)["passed"])
            shutil.copytree(sources[0], sources[3])
            rc, portable, html, history, summary = self.build(root, sources, "hold")
            self.assertEqual(rc, 2)
            self.assertEqual(summary["pairs_checked"], 6)
            self.assertFalse(summary["passed"])
            self.assertIn("HOLD is global", html)
            self.assertIn("HOLD pairs", html)
            self.assertIn("Evidence reused", html)
            self.assertIn("Review priorities", html)
            self.assertIn("Archive 1", html)
            self.assertIn("Archive 4", html)
            self.assertIn("history.html#pair-1-4", html)
            self.assertIn("id='pair-1-4'", history)
            self.assertIn("history.html#archive-1", html)
            self.assertIn("id='archive-1'", history)
            self.assertEqual(html.count("Open HOLD details"), 1)
            self.assertIn("HUMAN brief", html)
            self.assertNotIn(str(root), html)
            self.assertNotIn("original_private_receipt", html)
            dest = root / "hold-browser"
            status, output, error = invoke("--unpack-portable-review", portable,
                                           "--unpack-output-dir", dest)
            self.assertEqual((status, error), (2, ""))
            self.assertIn("status HOLD", output)
            self.assertIn("HOLD is global", (dest/"index.html").read_text())
            self.assertEqual(invoke("--verify-unpacked-review", portable,
                                    "--unpacked-review-dir", dest)[0], 2)
