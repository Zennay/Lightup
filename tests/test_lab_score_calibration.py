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
            self.assertEqual({p.name for p in root.iterdir()}, {"baseline", "candidate"})
            for p in (root, root/"baseline", root/"candidate"):
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
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
