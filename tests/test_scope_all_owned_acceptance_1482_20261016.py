"""#1482 full isolated ownership suite attestation is NEVER a release gate."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "scripts" / "check_scope_1482_all_owned_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_all_suite", PATH)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class AllOwnedSourcePinTests(unittest.TestCase):
    def test_empty_git_blob_sha_matches_canonical_git(self):
        self.assertEqual(review.git_blob_sha(b""),
                         "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_exact_fifteen_readable_pinned_blobs(self):
        self.assertEqual(len(review.PINNED_GIT_BLOBS), 15)
        self.assertTrue(review.pinned_tree_valid())

    def test_all_eight_owned_test_modules_included(self):
        self.assertEqual(len(review.TEST_PATTERNS), 8)
        self.assertEqual(len(set(review.TEST_PATTERNS)), 8)

    def test_manifest_contains_126_unique_named_cases(self):
        self.assertEqual(len(review.EXPECTED_TEST_IDS), 126)
        self.assertEqual(len(review.EXPECTED_OPEN_REDS), 3)
        self.assertTrue(review.EXPECTED_OPEN_REDS < review.EXPECTED_TEST_IDS)

    def test_invalid_root_fails_without_loading_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            out = io.StringIO()
            with patch.object(
                unittest.defaultTestLoader, "discover",
                side_effect=AssertionError("no discovery before hashes"),
            ), redirect_stdout(out):
                code = review.run(Path(directory))
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue().strip(), "HOLD: source_bytes")

    def test_invalid_hash_early_blocks_all_discovery(self):
        with patch.object(review, "pinned_tree_valid", return_value=False), \
             patch.object(unittest.defaultTestLoader, "discover",
                          side_effect=AssertionError("should never discover")):
            out = io.StringIO()
            with redirect_stdout(out):
                code = review.run()
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue().strip(), "HOLD: source_bytes")

    def test_empty_test_manifest_refuses(self):
        self.assertFalse(review.test_manifest_valid(unittest.TestSuite()))

    def test_any_missing_test_case_refuses(self):
        sys.path.insert(0, str(ROOT / "src"))
        source = unittest.defaultTestLoader.discover(
            str(ROOT / "tests"), pattern=review.TEST_PATTERNS[0]
        )
        self.assertFalse(review.test_manifest_valid(source))

    def test_arbitrary_empty_test_result_never_passes(self):
        self.assertFalse(review.test_result_valid(unittest.TestResult()))

    def test_real_126_case_isolated_full_source_proof(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = review.run()
        self.assertEqual(code, 0)
        self.assertIn("REVIEW_ONLY", out.getvalue())
        self.assertIn("3 ORIGINAL SOURCE REDs", out.getvalue())
        self.assertNotIn("GRANTED", out.getvalue())

    def test_actual_subprocess_cli_has_bounded_review_only_output(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, str(PATH)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertLess(len(result.stdout), 160)
        self.assertTrue(result.stdout.startswith("REVIEW_ONLY:"))
        self.assertIn("NO RELEASE", result.stdout)


if __name__ == "__main__":
    unittest.main()
