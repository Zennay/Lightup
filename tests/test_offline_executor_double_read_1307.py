"""W12 immutable *synthetic local input* double-read regression tests.

Never executes a tool or contacts a target; only a disposable local JSON file.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import (
    _load_plan, MAX_BYTES, InvalidSyntheticPlan,
)


class SecondReadIntegrity1307(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="lightup-w12-double-read-")
        self.addCleanup(d.cleanup)
        self.file = Path(d.name) / "one.json"
        self.plain = b'{"version":1,"tools":["offline-check-001"]}'
        self.changed = b'{"version":1,"tools":["offline-check-002"]}'
        self.assertEqual(len(self.plain), len(self.changed))
        self.file.write_bytes(self.plain)

    def _denied(self):
        with self.assertRaisesRegex(
            InvalidSyntheticPlan, "^synthetic offline preview denied$"
        ):
            _load_plan(str(self.file))

    def test_valid_plan_is_verified_twice_and_still_not_authorized(self):
        called = []
        original = os.read

        def audit(fd, budget):
            part = original(fd, budget)
            called.append((budget, len(part)))
            return part

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=audit):
            self.assertEqual(_load_plan(str(self.file)), ("offline-check-001",))
        self.assertEqual(
            called,
            [
                (MAX_BYTES + 1, len(self.plain)),
                (MAX_BYTES + 1 - len(self.plain), 0),
                (MAX_BYTES + 1, len(self.plain)),
                (MAX_BYTES + 1 - len(self.plain), 0),
            ],
        )

    def test_second_pass_detects_same_length_different_bytes_even_when_stat_unchanged(self):
        real_read = os.read
        first_pass_finished = False
        original_lseek = os.lseek

        def seek(fd, offset, whence):
            nonlocal first_pass_finished
            result = original_lseek(fd, offset, whence)
            first_pass_finished = True
            return result

        def read(fd, budget):
            chunk = real_read(fd, budget)
            if first_pass_finished and chunk == self.plain:
                return self.changed
            return chunk

        with patch("lightup.offline_executor_batch_cli_optin.os.lseek", side_effect=seek):
            with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=read):
                self._denied()

    def test_same_length_real_rewrite_with_forged_stable_stat_is_denied(self):
        real_read = os.read
        real_stat = os.fstat
        before_stat = self.file.stat()
        old = self.plain
        wrote = False

        def frozen_stat(fd):
            actual = real_stat(fd)
            # Pretend a malicious filesystem returns metadata from before
            # the rewrite: only the two byte reads may detect the change.
            class Frozen:
                def __getattr__(self, name):
                    if name == "st_ctime_ns":
                        return before_stat.st_ctime_ns
                    if name == "st_mtime_ns":
                        return before_stat.st_mtime_ns
                    return getattr(actual, name)
            return Frozen()

        def rewrite(fd, n):
            nonlocal wrote
            data = real_read(fd, n)
            if data == old and not wrote:
                wrote = True
                self.file.write_bytes(self.changed)
            return data

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=frozen_stat):
            with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=rewrite):
                self._denied()
        self.assertTrue(wrote)

    def test_truncated_second_pass_is_denied(self):
        read_fn, seek_fn = os.read, os.lseek
        second = False
        forced_eof = False

        def seek(fd, offset, whence):
            nonlocal second
            second = True
            return seek_fn(fd, offset, whence)

        def truncated(fd, n):
            nonlocal forced_eof
            if second:
                if forced_eof:
                    return b""
                forced_eof = True
                return read_fn(fd, min(n, 5))
            return read_fn(fd, n)

        with patch("lightup.offline_executor_batch_cli_optin.os.lseek", side_effect=seek):
            with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=truncated):
                self._denied()

    def test_second_pass_error_closes_every_open_fd(self):
        open_fn, close_fn, read_fn, seek_fn = os.open, os.close, os.read, os.lseek
        opened, closed = [], []
        second = False

        def track_open(*args, **kwargs):
            fd = open_fn(*args, **kwargs)
            opened.append(fd)
            return fd

        def track_close(fd):
            closed.append(fd)
            return close_fn(fd)

        def seek(fd, offset, whence):
            nonlocal second
            second = True
            return seek_fn(fd, offset, whence)

        def read(fd, count):
            if second:
                raise OSError("synthetic second-pass error")
            return read_fn(fd, count)

        with patch("lightup.offline_executor_batch_cli_optin.os.open", side_effect=track_open):
            with patch("lightup.offline_executor_batch_cli_optin.os.close", side_effect=track_close):
                with patch("lightup.offline_executor_batch_cli_optin.os.lseek", side_effect=seek):
                    with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=read):
                        with self.assertRaises(OSError):
                            _load_plan(str(self.file))
        self.assertEqual(opened, closed)

    def test_second_pass_uses_same_fd_and_rewinds_to_zero(self):
        seek_fn = os.lseek
        seeks = []

        def track(fd, offset, whence):
            seeks.append((fd, offset, whence))
            return seek_fn(fd, offset, whence)

        with patch("lightup.offline_executor_batch_cli_optin.os.lseek", side_effect=track):
            self.assertEqual(_load_plan(str(self.file)), ("offline-check-001",))
        self.assertEqual(len(seeks), 1)
        self.assertEqual(seeks[0][1:], (0, os.SEEK_SET))

    def test_short_kernel_reads_work_in_both_bounded_passes(self):
        read_fn = os.read
        calls = []

        def short(fd, budget):
            calls.append(budget)
            return read_fn(fd, min(3, budget))

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=short):
            self.assertEqual(_load_plan(str(self.file)), ("offline-check-001",))
        self.assertGreater(len(calls), 20)
        self.assertTrue(all(1 <= n <= MAX_BYTES + 1 for n in calls))

    def test_empty_regular_file_still_refused(self):
        self.file.write_bytes(b"")
        self._denied()


if __name__ == "__main__":
    unittest.main()
