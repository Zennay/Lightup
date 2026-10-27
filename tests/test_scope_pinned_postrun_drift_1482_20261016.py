"""Offline 1482: rehash full exact source tree after tests, still no release."""
import importlib.util
import io
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_scope_1482_all_owned_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_postrun_guard", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class SourceDriftAfterExecutionTests(unittest.TestCase):
    def test_current_real_126_case_pass_rechecks_source_twice(self):
        original = verifier.pinned_tree_valid
        with patch.object(verifier, "pinned_tree_valid", wraps=original) as spy:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(rc, 0)
        self.assertEqual(spy.call_count, 2)
        self.assertIn("REVIEW_ONLY", out.getvalue())
        self.assertIn("NO RELEASE", out.getvalue())

    def test_changed_hash_at_final_check_returns_hold(self):
        with patch.object(
            verifier, "pinned_tree_valid", side_effect=[True, False]
        ) as spy:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(spy.call_count, 2)
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue().strip(), "HOLD: source_changed_during_tests")

    def test_preflight_changed_source_refuses_execution(self):
        with patch.object(
            verifier, "pinned_tree_valid", return_value=False
        ) as spy, patch.object(
            unittest.defaultTestLoader, "discover",
            side_effect=AssertionError("no test discovery on invalid source"),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(rc, 2)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(out.getvalue().strip(), "HOLD: source_bytes")

    def test_arbitrary_runner_failure_does_not_bypass_posttest(self):
        with patch.object(
            verifier, "pinned_tree_valid", return_value=True
        ) as spy, patch.object(
            unittest.defaultTestLoader, "discover",
            side_effect=ValueError("synthetic runner failure"),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(rc, 2)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(out.getvalue().strip(), "HOLD: test_runtime")


if __name__ == "__main__":
    unittest.main()
