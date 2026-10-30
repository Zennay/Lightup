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

    def test_relative_calibration_path_cannot_be_redirected_by_cwd_change(self):
        with tempfile.TemporaryDirectory() as base:
            first, second = Path(base) / "first", Path(base) / "second"
            first.mkdir(mode=0o700)
            second.mkdir(mode=0o700)
            original = first / "calibration"
            alternate = second / "calibration"
            self.assertTrue(cal.run_lab_score_calibration(original)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(alternate)["passed"])
            # Original is now bound to a different valid saved receipt; a
            # process-wide chdir must not redirect its later source checks.
            (original / "report.json").write_bytes(
                (alternate / "report.json").read_bytes()
            )
            previous_cwd = Path.cwd()
            actual_compare = cal.compare_score_runs
            try:
                os.chdir(first)
                def change_cwd(*args):
                    os.chdir(second)
                    return actual_compare(*args)
                with patch.object(cal, "compare_score_runs", side_effect=change_cwd):
                    with self.assertRaises(ValueError):
                        cal.verify_saved_calibration("calibration")
            finally:
                os.chdir(previous_cwd)

    def test_standalone_comparator_freezes_both_relative_paths_before_read(self):
        from lightup import lab_score_compare as compare
        from lightup.lab_score_suite import run_lab_score_suite
        with tempfile.TemporaryDirectory() as base:
            first, second = Path(base) / "first", Path(base) / "second"
            first.mkdir(mode=0o700)
            second.mkdir(mode=0o700)
            self.assertTrue(run_lab_score_suite(first / "baseline")["passed"])
            self.assertTrue(run_lab_score_suite(first / "candidate")["passed"])
            previous_cwd = Path.cwd()
            original_inspect = compare.inspect_score_run
            inspected = []
            try:
                os.chdir(first)
                def change_cwd(path, **kwargs):
                    inspected.append(Path(path))
                    if len(inspected) == 1:
                        os.chdir(second)
                    return original_inspect(path, **kwargs)
                with patch.object(compare, "inspect_score_run", side_effect=change_cwd):
                    report = compare.compare_score_runs("baseline", "candidate")
                self.assertTrue(report["passed"])
                self.assertEqual(inspected, [
                    first / "baseline", first / "candidate"
                ])
            finally:
                os.chdir(previous_cwd)

    def test_comparator_resolves_pair_under_one_working_directory(self):
        from lightup import lab_score_compare as compare
        from lightup.lab_score_suite import run_lab_score_suite
        with tempfile.TemporaryDirectory() as base:
            saved = Path(base) / "saved"
            saved.mkdir(mode=0o700)
            self.assertTrue(run_lab_score_suite(saved / "baseline")["passed"])
            self.assertTrue(run_lab_score_suite(saved / "candidate")["passed"])
            original = Path.cwd()
            old_abspath = compare.os.path.abspath
            invocations = []
            def cwd_shift_after_first_resolution(value):
                result = old_abspath(value)
                invocations.append(str(value))
                if len(invocations) == 1:
                    os.chdir(base)
                return result
            try:
                os.chdir(saved)
                with patch.object(compare.os.path, "abspath",
                                  side_effect=cwd_shift_after_first_resolution):
                    report = compare.compare_score_runs("baseline", "candidate")
                self.assertTrue(report["passed"])
                self.assertEqual(invocations, [])
            finally:
                os.chdir(original)

    def test_compare_two_private_saved_calibrations_without_producers(self):
        with tempfile.TemporaryDirectory() as base:
            older, newer = Path(base)/"older", Path(base)/"newer"
            self.assertTrue(cal.run_lab_score_calibration(older)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(newer)["passed"])
            original = {(str(f), f.stat().st_mtime_ns) for root in (older,newer)
                        for f in root.rglob("*")}
            with patch.object(cal,"run_lab_score_suite",
                              side_effect=AssertionError("scorer re-executed")):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cal.main(["--compare-calibrations",str(older),str(newer),
                                     "--format","json"])
            self.assertEqual(code,0)
            report = json.loads(output.getvalue())
            self.assertTrue(report["passed"])
            self.assertTrue(report["comparison"]["independent_evaluations"])
            self.assertEqual(report["saved_runs"],["previous","current"])
            self.assertEqual(report["comparison_mode"],"archived_calibrations")
            self.assertNotIn(base,output.getvalue())
            self.assertEqual(original,{(str(f), f.stat().st_mtime_ns)
                                      for root in (older,newer) for f in root.rglob("*")})

    def test_archive_comparison_rejects_tampering_and_duplicate_runs(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            older, newer = Path(base)/"older", Path(base)/"newer"
            self.assertTrue(cal.run_lab_score_calibration(older)["passed"])
            shutil.copytree(older,newer)
            output=io.StringIO()
            with redirect_stdout(output):
                code=cal.main(["--compare-calibrations",str(older),str(newer),
                               "--format","json"])
            self.assertEqual(code,2)
            duplicate=json.loads(output.getvalue())
            self.assertFalse(duplicate["passed"])
            self.assertFalse(duplicate["comparison"]["independent_evaluations"])
            shutil.rmtree(newer)
            self.assertTrue(cal.run_lab_score_calibration(newer)["passed"])
            (newer/"report.json").write_bytes(b"corrupted")
            output,err=io.StringIO(),io.StringIO()
            with redirect_stdout(output),redirect_stderr(err):
                code=cal.main(["--compare-calibrations",str(older),str(newer)])
            self.assertEqual(code,2)
            self.assertEqual(output.getvalue(),"")
            self.assertIn("HOLD",err.getvalue())
            self.assertNotIn(base,err.getvalue())

    def test_archive_comparison_rejects_reused_baseline_from_other_archive(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            previous, current = Path(base)/"previous", Path(base)/"current"
            self.assertTrue(cal.run_lab_score_calibration(previous)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(current)["passed"])
            shutil.rmtree(current/"baseline")
            shutil.copytree(previous/"baseline", current/"baseline")
            candidate_comparison = cal.compare_score_runs(
                current/"baseline", current/"candidate")
            self.assertTrue(candidate_comparison["passed"])
            (current/"report.json").write_bytes(cal._receipt_bytes(cal._receipt(
                candidate_comparison,cal._source_hashes(current))))
            self.assertTrue(cal.verify_saved_calibration(current)["passed"])
            report=cal.compare_saved_calibrations(previous,current)
            self.assertFalse(report["passed"])
            self.assertFalse(report["comparison"]["independent_evaluations"])
            self.assertTrue(report["comparison"]["reused_archived_source"])
            self.assertTrue(all(
                not item["distinct_evaluation"]
                for item in report["comparison"]["capabilities"].values()))
            self.assertNotIn(base,str(report))

    def test_archive_comparison_refuses_source_change_after_score_read(self):
        # Both archives pass full receipt verification before comparison;
        # a later changed child artifact must never yield archived PASS.
        with tempfile.TemporaryDirectory() as base:
            previous, current = Path(base)/"previous", Path(base)/"current"
            self.assertTrue(cal.run_lab_score_calibration(previous)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(current)["passed"])
            actual = cal.compare_score_runs
            calls = []
            def change_after_score_read(*args):
                report = actual(*args)
                calls.append(1)
                if len(calls) == 3:
                    (current/"candidate"/"http_baseline.sqlite3").write_bytes(b"modified")
                return report
            out, err = io.StringIO(), io.StringIO()
            with patch.object(cal, "compare_score_runs",
                              side_effect=change_after_score_read):
                with redirect_stdout(out), redirect_stderr(err):
                    status = cal.main(["--compare-calibrations",
                                       str(previous), str(current),
                                       "--format", "json"])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(json.loads(err.getvalue()),
                             {"schema": cal.SCHEMA, "passed": False})
            self.assertNotIn(base, err.getvalue())
            self.assertEqual(len(calls), 3)

    def test_archive_comparison_rejects_root_replacement_mid_read(self):
        with tempfile.TemporaryDirectory() as base:
            previous, current = Path(base)/"previous", Path(base)/"current"
            alternate = Path(base)/"alternate"
            self.assertTrue(cal.run_lab_score_calibration(previous)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(current)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(alternate)["passed"])
            actual = cal.compare_score_runs
            calls = []
            def replace_before_final_compare(*args):
                calls.append(1)
                if len(calls) == 3:
                    current.rename(Path(base)/"old-current")
                    alternate.rename(current)
                return actual(*args)
            with patch.object(cal, "compare_score_runs",
                              side_effect=replace_before_final_compare):
                with self.assertRaisesRegex(ValueError, "archive substituted"):
                    cal.compare_saved_calibrations(previous, current)
            self.assertEqual(len(calls), 3)

    def test_three_original_archives_have_all_pairwise_checks_and_safe_output(self):
        with tempfile.TemporaryDirectory() as base:
            archives = [Path(base)/str(i) for i in range(3)]
            for root in archives:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            out = io.StringIO()
            with patch.object(cal, "run_lab_score_suite",
                              side_effect=AssertionError("producer re-executed")):
                with redirect_stdout(out):
                    code = cal.main(["--compare-history", *map(str, archives),
                                     "--format", "json"])
            self.assertEqual(code, 0)
            report = json.loads(out.getvalue())
            self.assertEqual(report["schema"], cal.HISTORY_SCHEMA)
            self.assertTrue(report["passed"])
            self.assertTrue(report["independent_evaluations"])
            self.assertEqual((report["archives_checked"], report["pairs_checked"]),
                             (3, 3))
            self.assertEqual(len(report["adjacent"]), 2)
            self.assertFalse(report["authorization_granted"])
            self.assertNotIn(base, out.getvalue())
            self.assertNotIn("sha256", out.getvalue())

    def test_history_rejects_nonadjacent_replayed_archive(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            first, second, third = [Path(base)/str(i) for i in range(3)]
            self.assertTrue(cal.run_lab_score_calibration(first)["passed"])
            self.assertTrue(cal.run_lab_score_calibration(second)["passed"])
            shutil.copytree(first, third)
            self.assertTrue(cal.compare_saved_calibrations(first, second)["passed"])
            self.assertTrue(cal.compare_saved_calibrations(second, third)["passed"])
            out = io.StringIO()
            with redirect_stdout(out):
                status = cal.main(["--compare-history", str(first), str(second),
                                   str(third), "--format", "json"])
            self.assertEqual(status, 2)
            result = json.loads(out.getvalue())
            self.assertFalse(result["passed"])
            self.assertFalse(result["independent_evaluations"])
            self.assertTrue(all(item["passed"] for item in result["adjacent"]))
            self.assertEqual(result["pairs_checked"], 3)
            self.assertNotIn(base, out.getvalue())
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                self.assertEqual(cal.main(["--compare-history", str(first)]), 2)
            self.assertIn("HOLD", err.getvalue())

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
