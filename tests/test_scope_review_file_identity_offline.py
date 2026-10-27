"""Fail-closed local-file identity regression for both offline-only checkers."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as single
import check_scope_review_batch_offline as batch


def metadata(original, **changes):
    keys = ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    values = {key: getattr(original, key) for key in keys}
    values.update(changes)
    return types.SimpleNamespace(**values)


class OfflineFileIdentityTests(unittest.TestCase):
    def readers(self):
        return (("single", single.read_packet, single.PacketHold, b"{}"),
                ("batch", batch.read_batch_file, batch.BatchHold, b"[]"))

    def test_unmodified_local_regular_file_read(self):
        for name, reader, _, contents in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "packet.json"
                file.write_bytes(contents)
                self.assertEqual(reader(str(file)), contents)

    def test_preopen_inode_substitution_is_hold(self):
        for name, reader, exception, contents in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "packet.json"
                file.write_bytes(contents)
                before = os.lstat(file)
                fake = metadata(before, st_ino=before.st_ino + 1)
                with mock.patch.object(os, "lstat", return_value=fake):
                    with self.assertRaises(exception) as ctx:
                        reader(str(file))
                self.assertEqual(ctx.exception.code, "CHANGED_INPUT")

    def test_preopen_same_inode_modified_mtime_is_hold(self):
        for name, reader, exception, contents in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "packet.json"
                file.write_bytes(contents)
                before = os.lstat(file)
                fake = metadata(before, st_mtime_ns=before.st_mtime_ns + 1)
                with mock.patch.object(os, "lstat", return_value=fake):
                    with self.assertRaises(exception) as ctx:
                        reader(str(file))
                self.assertEqual(ctx.exception.code, "CHANGED_INPUT")

    def test_after_read_same_length_rewrite_metadata_is_hold(self):
        for name, reader, exception, contents in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "packet.json"
                file.write_bytes(contents)
                original_fstat = os.fstat
                calls = [0]

                def changed_second_fstat(fd):
                    calls[0] += 1
                    info = original_fstat(fd)
                    if calls[0] == 2:
                        return metadata(info, st_ctime_ns=info.st_ctime_ns + 1)
                    return info

                with mock.patch.object(os, "fstat", side_effect=changed_second_fstat):
                    with self.assertRaises(exception) as ctx:
                        reader(str(file))
                self.assertEqual(ctx.exception.code, "CHANGED_INPUT")
                self.assertEqual(calls[0], 2)

    def test_symlink_disallowed_before_os_open(self):
        for name, reader, exception, contents in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "packet.json"
                file.write_bytes(contents)
                link = Path(d) / "symlink.json"
                link.symlink_to(file)
                with mock.patch.object(os, "open", side_effect=AssertionError("must not open link")):
                    with self.assertRaises(exception) as ctx:
                        reader(str(link))
                self.assertEqual(ctx.exception.code, "INPUT_UNAVAILABLE")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_disallowed_before_os_open(self):
        for name, reader, exception, _ in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "pipe.json"
                os.mkfifo(path)
                with mock.patch.object(os, "open", side_effect=AssertionError("must not open FIFO")):
                    with self.assertRaises(exception) as ctx:
                        reader(str(path))
                self.assertEqual(ctx.exception.code, "NOT_REGULAR_FILE")

    def test_invalid_file_type_no_privileged_side_effect(self):
        for name, reader, exception, _ in self.readers():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(exception) as ctx:
                    reader(d)
                self.assertEqual(ctx.exception.code, "NOT_REGULAR_FILE")

    def test_held_receipts_never_have_permissions(self):
        for evaluator in (single.evaluate, batch.evaluate):
            with self.subTest(evaluator=evaluator):
                result = evaluator(b"invalid")
                self.assertEqual(result["state"], "HOLD")
                self.assertTrue(result["non_authorizing"])
                for key in single.AUTHORITY_FLAGS:
                    self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
