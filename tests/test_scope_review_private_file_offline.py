"""Optional owner-only, single-link POSIX review-file privacy tests.

This is a local privacy lint: a passing receipt never authenticates scope or grants.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as single
import check_scope_review_batch_offline as batch


def clone(info, **updates):
    keys = ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
            "st_uid", "st_nlink")
    data = {key: getattr(info, key) for key in keys}
    data.update(updates)
    return types.SimpleNamespace(**data)


@unittest.skipUnless(hasattr(os, "geteuid") and hasattr(os, "chmod"), "POSIX permission model required")
class OfflinePrivateFileTests(unittest.TestCase):
    def readers(self):
        return ((single.read_packet, single.PacketHold, "check_scope_review_packet_offline.py", b"{}"),
                (batch.read_batch_file, batch.BatchHold, "check_scope_review_batch_offline.py", b"[]"))

    def _file(self, folder, raw=b"{}"):
        path = Path(folder) / "review-private.json"
        path.write_bytes(raw)
        return path

    def test_private_mode_accepts_owner_only_0600(self):
        for read, _, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o600)
                self.assertEqual(raw, read(str(path), require_private_file=True))

    def test_private_mode_accepts_owner_only_0400(self):
        for read, _, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o400)
                self.assertEqual(raw, read(str(path), require_private_file=True))

    def test_group_read_permission_denied_before_open(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o640)
                with mock.patch.object(os, "open", side_effect=AssertionError("cannot open insecure file")):
                    with self.assertRaises(err) as caught:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)

    def test_world_read_permission_denied_before_open(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o604)
                with mock.patch.object(os, "open", side_effect=AssertionError("cannot open insecure file")):
                    with self.assertRaises(err) as caught:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)

    def test_world_write_permission_denied(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o602)
                with self.assertRaises(err) as caught:
                    read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)

    def test_hardlink_denied_before_open(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o600)
                os.link(path, Path(d) / "second-link")
                with mock.patch.object(os, "open", side_effect=AssertionError("cannot open linked file")):
                    with self.assertRaises(err) as caught:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)

    def test_non_owner_denied_even_if_mode_0600(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o600)
                with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
                    with self.assertRaises(err) as caught:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)

    def test_descriptor_permission_downgrade_denied(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o600)
                real_fstat = os.fstat
                calls = [0]
                def fstat_changed(fd):
                    calls[0] += 1
                    info = real_fstat(fd)
                    if calls[0] == 2:
                        return clone(info, st_mode=info.st_mode | stat.S_IROTH)
                    return info
                with mock.patch.object(os, "fstat", side_effect=fstat_changed):
                    with self.assertRaises(err) as caught:
                        read(str(path), require_private_file=True)
                self.assertEqual("PRIVATE_FILE_REQUIRED", caught.exception.code)
                self.assertEqual(2, calls[0])

    def test_non_boolean_policy_rejected_without_open(self):
        for read, err, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                with mock.patch.object(os, "open", side_effect=AssertionError("unexpected open")):
                    for bad in (1, "true", None, [], False.__class__):
                        with self.assertRaises(err) as caught:
                            read(str(path), require_private_file=bad)
                        self.assertEqual("INVALID_FILE_POLICY", caught.exception.code)

    def test_default_remains_compatible_for_public_synthetic_file(self):
        for read, _, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o644)
                self.assertEqual(raw, read(str(path)))

    def test_private_cli_holds_on_world_readable_file_with_false_flags(self):
        for _, _, executable, raw in self.readers():
            with self.subTest(executable=executable), tempfile.TemporaryDirectory() as d:
                path = self._file(d, raw)
                path.chmod(0o644)
                run = subprocess.run(
                    [sys.executable, str(SCRIPTS / executable), "--require-private-file", str(path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(2, run.returncode)
                result = json.loads(run.stdout)
                self.assertEqual(("HOLD", "PRIVATE_FILE_REQUIRED"),
                                 (result["state"], result["reason"]))
                self.assertTrue(result["non_authorizing"])
                for key in single.AUTHORITY_FLAGS:
                    self.assertIs(result[key], False)
                self.assertFalse(run.stderr)

    def test_private_cli_retains_shape_only_semantics_for_owned_file(self):
        for _, _, executable, _ in self.readers():
            with self.subTest(executable=executable), tempfile.TemporaryDirectory() as d:
                path = self._file(d, b"{}" if "packet" in executable else b"[]")
                path.chmod(0o600)
                run = subprocess.run(
                    [sys.executable, str(SCRIPTS / executable), "--require-private-file", str(path)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(2, run.returncode)
                result = json.loads(run.stdout)
                self.assertEqual("HOLD", result["state"])  # file is private, content is malformed
                self.assertNotEqual("PRIVATE_FILE_REQUIRED", result["reason"])
                self.assertTrue(all(result[k] is False for k in single.AUTHORITY_FLAGS))


if __name__ == "__main__":
    unittest.main()
