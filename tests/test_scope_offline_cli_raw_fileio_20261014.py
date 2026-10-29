"""Isolated synthetic direct-FileIO regression for offline scope review (#1404).

This is a Python-level test tripwire, NEVER an OS filesystem sandbox or a
production authorization mechanism. No actual private files are accessed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scope_offline_cli_socket_fleet_20261014 import _TRIPWIRE

_REPO = Path(__file__).resolve().parents[1]
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)
# Augment the already verified main fleet test hook in a DISTINCT, opt-in
# subprocess fixture. Avoid editing another worker's live CLI or runtime.
# In particular, do not intercept _io.open_code: Python imports may use it.
_FILEIO_TRIPWIRE = _TRIPWIRE + """
import _io
# Direct raw file constructors can bypass os.open/os.read/builtins.open hooks.
# Abort before native raw file-object construction, even under catch-all.
io.FileIO = forbidden
_io.FileIO = forbidden
"""


class OfflineScopeRawFileIOTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-rawfileio-lab-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sitecustomize.py").write_text(
            _FILEIO_TRIPWIRE, encoding="utf-8"
        )
        (self.root / "synthetic-private.txt").write_text(
            "synthetic-no-customer-secret", encoding="utf-8"
        )
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_REPO / "src"), str(_REPO),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

    def fingerprint(self):
        return {
            str(file.relative_to(self.root)): hashlib.sha256(file.read_bytes()).hexdigest()
            for file in self.root.rglob("*") if file.is_file()
        }

    def run_child(self, program: str, payload: bytes = b""):
        return subprocess.run(
            [sys.executable, "-B", "-c", program],
            cwd=self.root, env=self.env, input=payload,
            capture_output=True, check=False, timeout=15,
        )

    def test_direct_fileio_paths_and_inherited_fds_abort_before_access(self):
        attempts = (
            'io.FileIO("synthetic-private.txt", "rb").read(1)',
            '_io.FileIO("synthetic-private.txt", "rb").read(1)',
            'io.FileIO(0, "rb", closefd=False).read(1)',
            '_io.FileIO(0, "rb", closefd=False).read(1)',
        )
        before = self.fingerprint()
        for statement in attempts:
            with self.subTest(statement=statement):
                program = (
                    "import io, _io\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('FALSE_REVIEW_ONLY')\n"
                )
                result = self.run_child(program)
                self.assertEqual(result.returncode, 92, statement)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")
                self.assertEqual(self.fingerprint(), before)

    def test_genuine_finite_number_cli_still_review_only_or_hold(self):
        script = _REPO / "scripts" / "review_scope_finite_number_offline.py"
        self.assertTrue(script.is_file())
        controls = (
            (b'{"arguments":[["synthetic",1.5]]}', 3, "REVIEW_ONLY"),
            (b'{"arguments":[["synthetic",NaN]]}', 2, "HOLD"),
        )
        before = self.fingerprint()
        for payload, code, expected in controls:
            with self.subTest(expected=expected):
                result = subprocess.run(
                    [sys.executable, "-B", str(script)], cwd=self.root,
                    env=self.env, input=payload, capture_output=True,
                    check=False, timeout=15,
                )
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], expected)
                for flag in _FLAGS:
                    self.assertIs(receipt[flag], False, flag)
                self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
