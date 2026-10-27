"""Synthetic short-read and file-change regression for both offline readers."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as single
import check_scope_review_batch_offline as batch


class OfflineBoundedReadTests(unittest.TestCase):
    def readers(self):
        return (
            (single.read_packet, single.PacketHold, b'{"fixture":"local"}'),
            (batch.read_batch_file, batch.BatchHold, b'[{"fixture":"local"}]'),
        )

    def setup(self, tmp, data):
        path = Path(tmp) / "review.json"
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_normal_reader_keeps_exact_bytes(self):
        for read, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                self.assertEqual(raw, read(str(path)))

    def test_single_byte_os_reads_still_return_entire_file(self):
        original = os.read
        for read, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                counts = [0]
                def short_read(fd, amount):
                    counts[0] += 1
                    return original(fd, min(amount, 1))
                with mock.patch.object(os, "read", side_effect=short_read):
                    result = read(str(path))
                self.assertEqual(raw, result)
                self.assertGreaterEqual(counts[0], len(raw))

    def test_single_byte_reads_with_private_dirfd_also_complete(self):
        original = os.read
        for read, _, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                with mock.patch.object(os, "read",
                                       side_effect=lambda fd, n: original(fd, min(1, n))):
                    result = read(str(path), require_private_file=True)
                self.assertEqual(raw, result)

    def test_transient_eof_after_first_byte_is_hold(self):
        original = os.read
        for read, exception, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                counter = [0]
                def interrupted(fd, n):
                    counter[0] += 1
                    return original(fd, 1) if counter[0] == 1 else b""
                with mock.patch.object(os, "read", side_effect=interrupted):
                    with self.assertRaises(exception) as held:
                        read(str(path))
                self.assertEqual("CHANGED_INPUT", held.exception.code)

    def test_append_during_read_refuses_changed_length(self):
        original = os.read
        for read, exception, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                appended = [False]
                def mutate(fd, n):
                    first = original(fd, min(n, 1))
                    if not appended[0]:
                        appended[0] = True
                        with path.open("ab") as out:
                            out.write(b"UNTRUSTED_APPEND")
                    return first
                with mock.patch.object(os, "read", side_effect=mutate):
                    with self.assertRaises(exception) as held:
                        read(str(path))
                self.assertEqual("CHANGED_INPUT", held.exception.code)
                self.assertTrue(appended[0])

    def test_replace_same_length_during_read_refuses_metadata_drift(self):
        original = os.read
        for read, exception, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, raw)
                mutated = [False]
                def mutate(fd, n):
                    first = original(fd, min(n, 1))
                    if not mutated[0]:
                        mutated[0] = True
                        with path.open("r+b") as output:
                            output.seek(0)
                            output.write(b"X")
                            output.flush()
                    return first
                with mock.patch.object(os, "read", side_effect=mutate):
                    with self.assertRaises(exception) as held:
                        read(str(path))
                self.assertEqual("CHANGED_INPUT", held.exception.code)

    def test_oversized_regular_file_denied_even_if_content_valid_json(self):
        for read, exception, raw in self.readers():
            with self.subTest(read=read.__name__), tempfile.TemporaryDirectory() as tmp:
                path = self.setup(tmp, b" " * ((single.MAX_BYTES if read is single.read_packet else batch.MAX_BATCH_BYTES) + 1))
                with self.assertRaises(exception) as held:
                    read(str(path))
                self.assertEqual("SIZE_LIMIT", held.exception.code)

    def test_bounded_reader_rejects_growth_over_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.setup(tmp, b"a")
            fd = os.open(path, os.O_RDONLY)
            try:
                real_read = os.read
                calls = [0]
                def out_of_bounds(fd, n):
                    calls[0] += 1
                    return b"A" * n if calls[0] == 1 else b""
                with mock.patch.object(os, "read", side_effect=out_of_bounds):
                    with self.assertRaises(single.PacketHold) as held:
                        single._read_bounded_regular(fd, 1, 10)
                self.assertEqual("SIZE_LIMIT", held.exception.code)
            finally:
                os.close(fd)

    def test_shared_reader_never_imports_authorizing_runtime(self):
        scripts = [SCRIPTS / "check_scope_review_packet_offline.py",
                   SCRIPTS / "check_scope_review_batch_offline.py"]
        for path in scripts:
            with self.subTest(name=path.name):
                code = path.read_text()
                for text in ("import requests", "import socket", "import subprocess",
                             "AuthorizationGrant", "ToolExecutor"):
                    self.assertNotIn(text, code)


if __name__ == "__main__":
    unittest.main()
