"""POSIX descriptor-relative private review intake: fail closed on path races."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as packet
import check_scope_review_batch_offline as batch


@unittest.skipUnless(
    hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
    and os.open in getattr(os, "supports_dir_fd", ()),
    "descriptor-relative POSIX open required")
class OfflineDirfdTests(unittest.TestCase):
    def readers(self):
        return (
            (packet.read_packet, packet.PacketHold, b"{}",
             "check_scope_review_packet_offline.py"),
            (batch.read_batch_file, batch.BatchHold, b"[]",
             "check_scope_review_batch_offline.py"),
        )

    def setup_file(self, base, raw):
        directory = Path(base) / "outer" / "nested"
        directory.mkdir(parents=True)
        path = directory / "review.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        return directory, path

    def test_owner_only_nested_file_read_succeeds(self):
        for read, _, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                _, path = self.setup_file(d, raw)
                self.assertEqual(raw, read(str(path), require_private_file=True))

    def test_reader_does_not_open_parent_symlinks(self):
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                link = directory.parent / "alias"
                link.symlink_to(directory, target_is_directory=True)
                with self.assertRaises(exception) as held:
                    read(str(link / "review.json"), require_private_file=True)
                self.assertEqual("PRIVATE_PARENT_SYMLINK", held.exception.code)

    def test_dirfd_rejects_parent_symlink_even_if_precheck_is_bypassed(self):
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                link = directory.parent / "alias"
                link.symlink_to(directory, target_is_directory=True)
                # A mocked inaccurate lstat precheck must never turn the actual
                # no-follow descriptor open into a symlink-following file open.
                with mock.patch.object(packet, "_enforce_private_ancestors", return_value=None):
                    with self.assertRaises(exception) as held:
                        read(str(link / "review.json"), require_private_file=True)
                self.assertEqual("INPUT_UNAVAILABLE", held.exception.code)

    def test_prechecked_parent_swapped_to_symlink_before_open_is_denied(self):
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                alternate = Path(d) / "attacker"
                alternate.mkdir()
                (alternate / "review.json").write_bytes(raw)
                (alternate / "review.json").chmod(0o600)
                moved = directory.parent / "saved-original"
                real_open = os.open
                triggered = [False]
                def race_open(p, flags, *args, **kwargs):
                    if p == "nested" and "dir_fd" in kwargs and not triggered[0]:
                        triggered[0] = True
                        directory.rename(moved)
                        directory.symlink_to(alternate, target_is_directory=True)
                    return real_open(p, flags, *args, **kwargs)
                with mock.patch.object(os, "open", side_effect=race_open) as wrapped:
                    with mock.patch.object(os, "supports_dir_fd",
                                           set(os.supports_dir_fd) | {wrapped}):
                        with self.assertRaises(exception) as held:
                            read(str(path), require_private_file=True)
                self.assertTrue(triggered[0])
                self.assertEqual("INPUT_UNAVAILABLE", held.exception.code)

    def test_prechecked_final_file_swapped_to_symlink_before_open_is_denied(self):
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                moved = directory / "original.json"
                real_open = os.open
                triggered = [False]
                def race_open(p, flags, *args, **kwargs):
                    if p == "review.json" and "dir_fd" in kwargs and not triggered[0]:
                        triggered[0] = True
                        path.rename(moved)
                        path.symlink_to(moved)
                    return real_open(p, flags, *args, **kwargs)
                with mock.patch.object(os, "open", side_effect=race_open) as wrapped:
                    with mock.patch.object(os, "supports_dir_fd",
                                           set(os.supports_dir_fd) | {wrapped}):
                        with self.assertRaises(exception) as held:
                            read(str(path), require_private_file=True)
                self.assertTrue(triggered[0])
                self.assertEqual("INPUT_UNAVAILABLE", held.exception.code)

    def test_missing_dirfd_support_is_hold_not_fallback(self):
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                _, path = self.setup_file(d, raw)
                with mock.patch.object(os, "supports_dir_fd", set()):
                    with self.assertRaises(exception) as held:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_PATH_UNSUPPORTED", held.exception.code)

    def test_without_private_flag_backwards_compatible_on_non_dirfd_system(self):
        for read, _, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                _, path = self.setup_file(d, raw)
                with mock.patch.object(os, "supports_dir_fd", set()):
                    self.assertEqual(raw, read(str(path)))

    def test_normal_private_open_uses_descriptor_relative_no_follow(self):
        for read, _, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                _, path = self.setup_file(d, raw)
                original_open = os.open
                records = []
                def intercept(name, flags, *args, **kwargs):
                    records.append((name, flags, kwargs.get("dir_fd")))
                    return original_open(name, flags, *args, **kwargs)
                with mock.patch.object(os, "open", side_effect=intercept) as wrapper:
                    with mock.patch.object(os, "supports_dir_fd",
                                           set(os.supports_dir_fd) | {wrapper}):
                        self.assertEqual(raw, read(str(path), require_private_file=True))
                self.assertGreaterEqual(len(records), 3)
                for name, flags, fd in records:
                    self.assertTrue(flags & os.O_NOFOLLOW, name)
                self.assertEqual(records[-1][0], "review.json")
                self.assertIsInstance(records[-1][2], int)

    def test_private_read_has_no_file_descriptor_leak(self):
        if not Path("/proc/self/fd").exists():
            self.skipTest("requires /proc FD inspection")
        for read, exception, raw, _ in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                before = len(list(Path("/proc/self/fd").iterdir()))
                for _ in range(25):
                    self.assertEqual(raw, read(str(path), require_private_file=True))
                after = len(list(Path("/proc/self/fd").iterdir()))
                self.assertEqual(before, after)

    def test_private_cli_does_not_expose_file_path_on_denial(self):
        for _, _, raw, script in self.readers():
            with self.subTest(script=script), tempfile.TemporaryDirectory() as d:
                directory, path = self.setup_file(d, raw)
                link = directory.parent / "SECRET-alias"
                link.symlink_to(directory, target_is_directory=True)
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / script),
                     "--require-private-file", str(link / "review.json")],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(2, result.returncode)
                self.assertNotIn("SECRET", result.stdout + result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual("HOLD", receipt["state"])
                self.assertTrue(all(receipt[key] is False for key in packet.AUTHORITY_FLAGS))

    def test_batch_source_can_reject_swapped_parent_without_changing_main(self):
        with tempfile.TemporaryDirectory() as d:
            _, source = self.setup_file(d, b"[]")
            self.assertEqual(b"[]", batch.read_batch_file(str(source), require_private_file=True))
            self.assertFalse(any(packet.AUTHORITY_FLAGS.values()))


if __name__ == "__main__":
    unittest.main()
