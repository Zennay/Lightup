"""W6 local file-descriptor admission: never block on special input files.

These tests exercise the real offline-only CLI as subprocesses. No external
targets, network calls, granted scopes, or handlers are ever executed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import _load_plan, InvalidSyntheticPlan, MAX_BYTES


class OfflinePlanFdAdmission1307(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-w6-fd-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.valid = self.root / "valid.json"
        self.valid.write_text(
            '{"version":1,"tools":["offline-check-001"]}', encoding="utf-8"
        )
        self.fifo = self.root / "never-open-in-blocking-mode"
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.fifo)

    def _run(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             *map(str, arguments)],
            capture_output=True, check=False, timeout=4,
        )

    def _denied(self, *arguments):
        p = self._run(*arguments)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")
        self.assertEqual(p.stderr, b"synthetic offline preview denied\n")
        for a in arguments:
            self.assertNotIn(str(a).encode("utf-8"), p.stderr)

    def test_valid_regular_file_is_still_accepted_by_real_cli(self):
        p = self._run("--input", self.valid)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["tools_reviewed"], 1)
        self.assertEqual(p.stderr, b"")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")
    def test_fifo_input_returns_deny_without_waiting_for_writer(self):
        self._denied("--input", self.fifo)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")
    def test_fifo_late_proposal_does_not_block_or_emit_partial_result(self):
        self._denied("--compare", self.valid, self.fifo)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")
    def test_fifo_baseline_denied_without_reading_proposal(self):
        self._denied("--compare", self.fifo, self.valid)

    def test_symlink_to_valid_plan_is_denied_without_following(self):
        link = self.root / "plan-alias"
        link.symlink_to(self.valid)
        self._denied("--input", link)

    def test_symlink_with_late_comparison_rejects_all(self):
        link = self.root / "proposal-alias"
        link.symlink_to(self.valid)
        self._denied("--compare", self.valid, link)

    def test_dangling_symlink_is_denied_opaquely(self):
        link = self.root / "missing-alias"
        link.symlink_to(self.root / "missing-plan")
        self._denied("--input", link)

    def test_regular_directory_cannot_be_read_as_plan(self):
        self._denied("--input", self.root)

    def test_platform_character_device_is_not_an_input_plan(self):
        if not Path("/dev/null").exists():
            self.skipTest("no /dev/null on this platform")
        self._denied("--input", "/dev/null")

    def test_oversized_sparse_file_is_denied_before_stream_read(self):
        giant = self.root / "sparse-plan.json"
        with giant.open("wb") as f:
            f.truncate(50 * 1024 * 1024)
        self._denied("--input", giant)

    def test_normal_maximum_size_regular_file_stays_parsable(self):
        # Trailing whitespace reaches exactly MAX_BYTES without adding scope.
        encoded = self.valid.read_bytes()
        self.assertLess(len(encoded), MAX_BYTES)
        self.valid.write_bytes(encoded + b" " * (MAX_BYTES - len(encoded)))
        self.assertEqual(_load_plan(str(self.valid)), ("offline-check-001",))

    def test_fd_open_uses_nonblocking_nofollow_and_cloexec(self):
        required = ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")
        if any(not hasattr(os, f) for f in required):
            self.skipTest("required platform flags missing; CLI itself denies")
        original = os.open
        with patch(
            "lightup.offline_executor_batch_cli_optin.os.open",
            wraps=original,
        ) as spy:
            result = _load_plan(str(self.valid))
        self.assertEqual(result, ("offline-check-001",))
        flagset = spy.call_args.args[1]
        for name in required:
            with self.subTest(name=name):
                self.assertTrue(flagset & getattr(os, name))

    def test_identity_pinned_to_same_descriptor_at_fstat(self):
        original = os.fstat
        calls = 0

        def fake_fstat(fd):
            nonlocal calls
            calls += 1
            value = original(fd)
            if calls == 2:
                return os.stat_result((
                    value.st_mode, value.st_ino, value.st_dev,
                    value.st_nlink, value.st_uid, value.st_gid,
                    value.st_size + 1, value.st_atime, value.st_mtime, value.st_ctime,
                ))
            return value

        with patch(
            "lightup.offline_executor_batch_cli_optin.os.fstat",
            side_effect=fake_fstat,
        ):
            with self.assertRaisesRegex(InvalidSyntheticPlan, "synthetic offline preview denied"):
                _load_plan(str(self.valid))
        self.assertGreaterEqual(calls, 2)

    def test_input_file_permission_bits_dont_change_receipt_authority(self):
        self.valid.chmod(stat.S_IRUSR)
        p = self._run("--input", self.valid)
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout)
        self.assertFalse(result["permit_issued"])
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["authorization_verified"])


if __name__ == "__main__":
    unittest.main()
