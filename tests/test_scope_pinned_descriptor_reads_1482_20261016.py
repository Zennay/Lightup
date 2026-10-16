"""#1482: only disposable local fds; anchored nofollow source reader contract.

The reviewed primitive never issues execution authority, opens sockets,
contacts targets or imports code from synthetic files.
"""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_scope_1482_all_owned_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_nofollow_attest", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def build(root):
    pins = {}
    for index in range(15):
        relative = f"source{index % 3}/nested_{index}/module_{index}.py"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = f"fictional #{index}".encode("ascii")
        path.write_bytes(data)
        pins[relative] = verifier.git_blob_sha(data)
    return pins


class DescriptorPinnedSourceTests(unittest.TestCase):
    def test_real_current_repository_tree_readable_without_indirection(self):
        self.assertTrue(verifier.pinned_tree_valid())

    def test_valid_disposable_tree_uses_descriptor_anchored_reads(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            with patch.object(verifier, "PINNED_GIT_BLOBS", pins):
                self.assertTrue(verifier.pinned_tree_valid(root))

    def test_direct_reader_matches_exact_content(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            first = next(iter(pins))
            payload = verifier._read_pinned_regular_file(root, tuple(first.split("/")))
            self.assertEqual(payload, (root / first).read_bytes())

    def test_strict_reader_does_not_call_path_open(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            with patch.object(Path, "open", side_effect=AssertionError("path reopened")), \
                 patch.object(verifier, "PINNED_GIT_BLOBS", pins):
                self.assertTrue(verifier.pinned_tree_valid(root))

    def test_leaf_swapped_to_same_hash_symlink_before_open_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            path = root / next(iter(pins))
            old = root / "original"
            backup = path.read_bytes()
            old.write_bytes(backup)
            actual_open = os.open
            did_swap = [False]
            def race(pathname, flags, *args, **kwargs):
                if not did_swap[0] and pathname == path.name and kwargs.get("dir_fd") is not None:
                    did_swap[0] = True
                    path.unlink()
                    path.symlink_to(old)
                return actual_open(pathname, flags, *args, **kwargs)
            with patch.object(verifier, "PINNED_GIT_BLOBS", pins), \
                 patch.object(verifier.os, "open", side_effect=race):
                self.assertFalse(verifier.pinned_tree_valid(root))
            self.assertTrue(did_swap[0])

    def test_parent_swapped_to_symlink_during_open_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            parent = root / "source0"
            backup = root / "moved"
            actual_open = os.open
            did_swap = [False]
            def race(pathname, flags, *args, **kwargs):
                if not did_swap[0] and pathname == "source0" and kwargs.get("dir_fd") is not None:
                    did_swap[0] = True
                    parent.rename(backup)
                    parent.symlink_to(backup, target_is_directory=True)
                return actual_open(pathname, flags, *args, **kwargs)
            with patch.object(verifier, "PINNED_GIT_BLOBS", pins), \
                 patch.object(verifier.os, "open", side_effect=race):
                self.assertFalse(verifier.pinned_tree_valid(root))
            self.assertTrue(did_swap[0])

    def test_fifo_leaf_refused_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO not available on this host")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / "fifo"
            parent.mkdir()
            fifo = parent / "data"
            os.mkfifo(fifo)
            with self.assertRaises(OSError):
                verifier._read_pinned_regular_file(root, ("fifo", "data"))

    def test_directory_cannot_be_read_as_regular_leaf(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "source").mkdir()
            with self.assertRaises(OSError):
                verifier._read_pinned_regular_file(root, ("source",))

    def test_symlinked_root_reader_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real"
            real.mkdir()
            pins = build(real)
            link = root / "alias"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                verifier._read_pinned_regular_file(
                    link, tuple(next(iter(pins)).split("/"))
                )

    def test_symlinked_leaf_reader_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            key = next(iter(pins))
            original = root / key
            backup = root / "safe"
            backup.write_bytes(original.read_bytes())
            original.unlink()
            original.symlink_to(backup)
            with self.assertRaises(OSError):
                verifier._read_pinned_regular_file(root, tuple(key.split("/")))

    def test_fail_closed_when_nofollow_support_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            with patch.object(verifier.os, "O_NOFOLLOW", None), \
                 patch.object(verifier, "PINNED_GIT_BLOBS", pins):
                self.assertFalse(verifier.pinned_tree_valid(root))

    def test_no_file_descriptor_leak_after_repeated_runs(self):
        directory = Path("/proc/self/fd")
        if not directory.is_dir():
            self.skipTest("procfs fd introspection unavailable")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pins = build(root)
            before = len(tuple(directory.iterdir()))
            with patch.object(verifier, "PINNED_GIT_BLOBS", pins):
                for _ in range(12):
                    self.assertTrue(verifier.pinned_tree_valid(root))
            after = len(tuple(directory.iterdir()))
            self.assertLessEqual(after - before, 1)

    def test_oversized_file_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "huge"
            p.write_bytes(b"x" * (verifier.MAX_BYTES + 1))
            with self.assertRaises(OSError):
                verifier._read_pinned_regular_file(root, ("huge",))


if __name__ == "__main__":
    unittest.main()
