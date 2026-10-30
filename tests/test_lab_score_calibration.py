"""Synthetic-only two-run calibration integration and safety checks."""
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_score_calibration as cal
from lightup.lab_score_inspect import inspect_score_run


class CalibrationTests(unittest.TestCase):
    def test_real_private_calibration_and_json(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "PRIVATE"
            old = os.umask(0o022)
            try:
                out = io.StringIO()
                with redirect_stdout(out):
                    code = cal.main(["--output-dir", str(root), "--format", "json"])
            finally:
                os.umask(old)
            self.assertEqual(code, 0)
            report = json.loads(out.getvalue())
            self.assertTrue(report["passed"])
            self.assertTrue(report["comparison"]["independent_evaluations"])
            self.assertEqual(report["saved_runs"], ["baseline", "candidate"])
            self.assertFalse(report["authorization_granted"])
            self.assertNotIn(base, out.getvalue())
            self.assertEqual({p.name for p in root.iterdir()}, {"baseline", "candidate", "report.json"})
            for p in (root, root/"baseline", root/"candidate"):
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root/"report.json").stat().st_mode), 0o600)
            stored = json.loads((root/"report.json").read_text())
            self.assertEqual({k: v for k, v in stored.items()
                              if k != "source_sha256"}, report)
            self.assertNotIn("source_sha256", out.getvalue())
            for name in ("baseline", "candidate"):
                self.assertEqual(set(stored["source_sha256"][name]),
                                 {"report.json", "service_inventory.sqlite3",
                                  "tls_baseline.sqlite3", "http_baseline.sqlite3"})
                self.assertTrue(all(len(digest) == 64 for digest
                                    in stored["source_sha256"][name].values()))
            for name in ("baseline", "candidate"):
                d = root/name
                self.assertTrue(inspect_score_run(d)["passed"])
                self.assertEqual(len(list(d.iterdir())), 4)
                for p in d.iterdir():
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_private_text_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/"result"
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--output-dir", str(root)])
            self.assertEqual(status, 0, err.getvalue())
            self.assertIn("score comparison: PASS", out.getvalue())
            self.assertIn("Authority: none", out.getvalue())
            self.assertNotIn(base, out.getvalue())
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--output-dir", str(root)])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("HOLD", err.getvalue())
            self.assertNotIn(base, err.getvalue())

    def test_reopen_saved_calibration_without_running_producers(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "private"
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            before = {(p.name, p.stat().st_ino, p.stat().st_mtime_ns)
                      for d in root.iterdir() if d.is_dir() for p in d.iterdir()}
            with patch.object(cal, "run_lab_score_suite",
                              side_effect=AssertionError("producer invoked")):
                out = io.StringIO()
                with redirect_stdout(out):
                    status = cal.main(["--verify-output-dir", str(root),
                                       "--format", "json"])
            self.assertEqual(status, 0)
            report = json.loads(out.getvalue())
            self.assertTrue(report["passed"])
            self.assertEqual(report["saved_runs"], ["baseline", "candidate"])
            self.assertNotIn(base, out.getvalue())
            self.assertEqual(before, {
                (p.name, p.stat().st_ino, p.stat().st_mtime_ns)
                for d in root.iterdir() if d.is_dir() for p in d.iterdir()
            })

    def test_verify_rejects_tampering_and_symlinked_saved_runs(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/"private"
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            (root/"EXTRA").write_text("unexpected")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--verify-output-dir", str(root)])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn(base, err.getvalue())
            (root/"EXTRA").unlink()
            (root/"candidate").rename(Path(base)/"outside")
            (root/"candidate").symlink_to(Path(base)/"outside", target_is_directory=True)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--verify-output-dir", str(root)])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("HOLD", err.getvalue())
            self.assertNotIn(base, err.getvalue())

    def test_calibration_receipt_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/"calibration"
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            receipt = root/"report.json"
            raw = json.loads(receipt.read_text())
            raw["passed"] = False
            receipt.write_text(json.dumps(raw, indent=2, sort_keys=True)+"\n")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = cal.main(["--verify-output-dir", str(root)])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("HOLD", err.getvalue())
            self.assertNotIn(base, err.getvalue())

    def test_missing_or_symlinked_receipt_refused(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/"calibration"
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            receipt = root/"report.json"
            receipt.rename(Path(base)/"moved.json")
            with self.assertRaises(ValueError):
                cal.verify_saved_calibration(root)
            receipt.symlink_to(Path(base)/"moved.json")
            with self.assertRaises(OSError):
                cal.verify_saved_calibration(root)

    def test_valid_independent_replacement_fails_source_binding(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            first = Path(base)/"first"
            alternative = Path(base)/"alternative"
            self.assertTrue(cal.run_lab_score_calibration(first)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(alternative)["passed"])
            shutil.rmtree(first/"candidate")
            shutil.copytree(alternative/"candidate", first/"candidate")
            # Scores still match and both source bundles remain valid, but
            # the persisted receipt must bind the exact saved source bytes.
            self.assertTrue(cal.compare_score_runs(
                first/"baseline", first/"candidate")["passed"])
            with self.assertRaises(ValueError):
                cal.verify_saved_calibration(first)

    def test_failed_producer_and_readback_never_publish_pass(self):
        with tempfile.TemporaryDirectory() as base:
            with patch.object(cal, "run_lab_score_suite", return_value={"passed": False}) as fn:
                with self.assertRaises(ValueError):
                    cal.run_lab_score_calibration(Path(base)/"first")
                self.assertEqual(fn.call_count, 1)
            with patch.object(cal, "run_lab_score_suite", side_effect=[
                {"passed": True}, {"passed": False}
            ]) as fn:
                with self.assertRaises(ValueError):
                    cal.run_lab_score_calibration(Path(base)/"second")
                self.assertEqual(fn.call_count, 2)
            with patch.object(cal, "run_lab_score_suite", return_value={"passed": True}), patch.object(
                cal, "compare_score_runs", side_effect=ValueError("PRIVATE " + base)
            ):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    status = cal.main(["--output-dir", str(Path(base)/"readback"), "--format", "json"])
                self.assertEqual(status, 2)
                self.assertEqual(out.getvalue(), "")
                self.assertEqual(json.loads(err.getvalue()), {"schema": cal.SCHEMA, "passed": False})


if __name__ == "__main__":
    unittest.main()
