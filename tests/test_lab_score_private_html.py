"""Private, no-overwrite HTML report delivery in synthetic assessment mode."""
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from lightup import lab_score_calibration as cal


class PrivateHtmlDeliveryTests(unittest.TestCase):
    def archives(self, base):
        roots = [Path(base)/str(i) for i in range(2)]
        for root in roots:
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
        return roots

    def invoke(self, roots, destination):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = cal.main(["--compare-history", *map(str, roots),
                               "--format", "html",
                               "--html-output-dir", str(destination)])
        return status, out.getvalue(), err.getvalue()

    def test_0600_atomic_new_report_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            dest = Path(base)/"private-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual((code, out, err), (0, "", ""))
            report = dest/"history.html"
            content = report.read_bytes()
            self.assertTrue(content.startswith(b"<!doctype html>"))
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertEqual(set(os.listdir(dest)), {"history.html"})
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not saved", err)
            self.assertNotIn(base, err)
            self.assertEqual(report.read_bytes(), content)

    def test_post_link_tamper_is_detected_and_report_removed(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            original_link = cal.os.link
            def mutate_published_report(*args, **kwargs):
                original_link(*args, **kwargs)
                if len(args) > 1 and args[1] == "history.html":
                    fd = os.open("history.html", os.O_WRONLY,
                                 dir_fd=kwargs["dst_dir_fd"])
                    try:
                        os.write(fd, b"CORRUPTED")
                    finally:
                        os.close(fd)
            dest = Path(base)/"tampered-review"
            with patch.object(cal.os, "link",
                              side_effect=mutate_published_report):
                code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("HTML review not saved", err)
            self.assertNotIn(base, err)
            self.assertFalse((dest/"history.html").exists())
            self.assertFalse((dest/".history.html.tmp").exists())

    def test_corrupt_source_refuses_to_create_report(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            (roots[1]/"report.json").write_bytes(b"invalid original")
            dest = Path(base)/"new-private-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("archive 2 not verified", err)
            self.assertFalse(dest.exists())
            self.assertNotIn(base, err)

    def test_symlinked_output_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            actual = Path(base)/"actual"
            actual.mkdir(mode=0o700)
            (Path(base)/"alias").symlink_to(actual, target_is_directory=True)
            code, out, err = self.invoke(roots, Path(base)/"alias"/"review")
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertFalse((actual/"review").exists())
            self.assertNotIn(base, err)

    def test_verified_hold_saves_private_report_and_returns_two(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            shutil.rmtree(roots[1])
            shutil.copytree(roots[0], roots[1])
            dest = Path(base)/"hold-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual((out, err), ("", ""))
            report = dest/"history.html"
            self.assertIn("Overall: HOLD", report.read_text())
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
