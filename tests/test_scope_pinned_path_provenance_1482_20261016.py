"""Negative offline provenance checks for the #1482 owned-source verifier.

Exercises disposable temp trees only; never changes real repository content.
"""
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_scope_1482_all_owned_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_adversarial", SCRIPT)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def make_fixture(root):
    """Exact 15 local fake blob pins; no original project files touched."""
    pins = {}
    for i in range(15):
        relative = f"pkg{i % 3}/nested_{i}/blob_{i}.py"
        contents = ("fictional scoped file #" + str(i)).encode()
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        pins[relative] = verify.git_blob_sha(contents)
    return pins


class SourcePathProvenanceAdversarialTests(unittest.TestCase):
    def test_actual_current_pinned_original_tree_positive(self):
        self.assertTrue(verify.pinned_tree_valid())

    def test_disposable_exact_15_files_positive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertTrue(verify.pinned_tree_valid(root))

    def test_symlinked_leaf_denied_even_with_identical_content(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            key = next(iter(pins))
            leaf = root / key
            replacement = root / "identical.txt"
            replacement.write_bytes(leaf.read_bytes())
            leaf.unlink()
            leaf.symlink_to(replacement)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_symlinked_parent_directory_denied_even_with_identical_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            old = root / "pkg0"
            moved = root / "real-pkg0"
            old.rename(moved)
            old.symlink_to(moved, target_is_directory=True)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_symlinked_nested_directory_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            nested = root / "pkg0/nested_0"
            moved = root / "moved_subdir"
            nested.rename(moved)
            nested.symlink_to(moved, target_is_directory=True)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_symlinked_root_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "real"
            root.mkdir()
            pins = make_fixture(root)
            alias = base / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(alias))

    def test_removed_blob_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            (root / next(iter(pins))).unlink()
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_one_bit_source_drift_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            leaf = root / next(iter(pins))
            leaf.write_bytes(leaf.read_bytes() + b"!")
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_less_than_15_manifest_paths_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            pins.pop(next(iter(pins)))
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_parent_traversal_entry_denied_before_open(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            value = pins.pop(next(iter(pins)))
            pins["pkg0/../fake.py"] = value
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_absolute_path_entry_denied_before_open(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            value = pins.pop(next(iter(pins)))
            pins["/tmp/fake-outside-1482"] = value
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_malformed_digest_string_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            pins[next(iter(pins))] = "made-up"
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_oversized_blob_denied_even_if_digest_matches(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = make_fixture(root)
            key = next(iter(pins))
            contents = b"a" * (verify.MAX_BYTES + 1)
            (root / key).write_bytes(contents)
            pins[key] = verify.git_blob_sha(contents)
            with patch.object(verify, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verify.pinned_tree_valid(root))

    def test_missing_source_never_starts_test_discovery(self):
        with tempfile.TemporaryDirectory() as td:
            out = io.StringIO()
            with patch.object(
                unittest.defaultTestLoader, "discover",
                side_effect=AssertionError("must never discover"),
            ), redirect_stdout(out):
                code = verify.run(Path(td))
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue().strip(), "HOLD: source_bytes")

    def test_expected_failure_as_arbitrary_exception_does_not_pass(self):
        result = unittest.TestResult()
        result.testsRun = len(verify.EXPECTED_TEST_IDS)
        fake = [(unittest.FunctionTestCase(lambda: None), "RuntimeError: masked original")]
        result.expectedFailures = fake * 3
        self.assertFalse(verify.test_result_valid(result))

    def test_replaced_expected_success_fails_closed(self):
        result = unittest.TestResult()
        result.testsRun = len(verify.EXPECTED_TEST_IDS)
        result.unexpectedSuccesses = [unittest.FunctionTestCase(lambda: None)]
        self.assertFalse(verify.test_result_valid(result))


if __name__ == "__main__":
    unittest.main()
