"""Independent positive and fail-closed checks for #1482 strict offline runner."""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
SCRIPT = ROOT / "scripts" / "check_scope_1482_source_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class StrictOfflineSourceAcceptanceTests(unittest.TestCase):
    def test_canonical_empty_git_blob_hash(self):
        self.assertEqual(
            verifier.git_blob_hash(b""),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        )

    def test_current_exact_reviewed_bytes_match(self):
        self.assertTrue(verifier.source_tree_ok())
        self.assertEqual(len(verifier.PINNED_BLOBS), 5)

    def test_mismatched_digest_fails_closed(self):
        wrong = dict(verifier.PINNED_BLOBS)
        wrong["src/lightup/activation.py"] = "0" * 40
        self.assertFalse(verifier.source_tree_ok(verifier.ROOT, wrong))

    def test_missing_reviewed_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as place:
            self.assertFalse(verifier.source_tree_ok(Path(place)))

    def test_exact_manifest_has_18_unique_methods(self):
        suite = unittest.defaultTestLoader.discover(
            str(HERE),
            pattern="test_scope_decision_shape_activation_1482_20261016.py",
        )
        self.assertTrue(verifier.manifest_ok(suite))
        self.assertEqual(len(verifier.ALL_IDS), 18)
        self.assertEqual(len(verifier.EXPECTED_SOURCE_REDS), 3)

    def test_manifest_detects_removed_case(self):
        suite = unittest.defaultTestLoader.discover(
            str(HERE),
            pattern="test_scope_decision_shape_activation_1482_20261016.py",
        )
        cases = list(verifier.flatten(suite))
        self.assertFalse(verifier.manifest_ok(unittest.TestSuite(cases[:-1])))

    def test_source_drift_never_executes_a_test(self):
        with patch.object(verifier, "source_tree_ok", return_value=False), \
             patch.object(
                 unittest.defaultTestLoader, "discover",
                 side_effect=AssertionError("discovery must not happen"),
             ):
            output = io.StringIO()
            with redirect_stdout(output):
                code = verifier.run()
        self.assertEqual(code, 2)
        self.assertEqual(output.getvalue().strip(), "HOLD: source_integrity")

    def test_fabricated_result_cannot_claim_success(self):
        self.assertFalse(verifier.result_ok(unittest.TestResult()))

    def test_real_isolated_18_method_source_acceptance(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = verifier.run()
        self.assertEqual(code, 0)
        self.assertIn("REVIEW_ONLY", out.getvalue())
        self.assertNotIn("AUTHORIZED:", out.getvalue())


if __name__ == "__main__":
    unittest.main()
