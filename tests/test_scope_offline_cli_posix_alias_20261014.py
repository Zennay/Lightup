"""Protect direct posix C-module aliases in offline scope-review synthetic CI.

This is Python-only test instrumentation (#1420), NOT an OS sandbox or
trusted authorization for any active customer target or assessment.
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
_SCRIPTS = _REPO / "scripts"
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)
# The posix module exports direct C function aliases independently from the
# public os module symbols. Monkeypatches here are installed pre-CLI import.
# Importlib and other native syscall consumers remain outside this fixture.
_POSIX_ALIAS_TRIPWIRE = _TRIPWIRE + """
try:
    import posix as _posix
except ImportError:
    _posix = None

if _posix is not None:
    _importer_listdir = _posix.listdir
    for _name in (
        "open", "read", "readv", "pread", "preadv",
        "write", "writev", "pwrite", "pwritev",
        "scandir", "walk", "fwalk",
        "dup", "dup2", "dup3", "closerange", "close_range",
        "fork", "forkpty", "system", "popen", "posix_spawn", "posix_spawnp",
        "execv", "execve", "execvp", "execvpe",
    ):
        if hasattr(_posix, _name):
            setattr(_posix, _name, forbidden)

    # CPython's frozen FileFinder._fill_cache calls posix.listdir directly
    # while importing trusted Python modules. Never allow arbitrary caller
    # directory enumeration; only this exact importer frame may list its
    # import path before normal offline CLI code executes.
    def _guarded_posix_listdir(*args, **kwargs):
        import sys as _sys
        try:
            _frame = _sys._getframe(1)
            if (_frame.f_code.co_name == "_fill_cache"
                    and _frame.f_globals.get("__name__") in (
                        "importlib._bootstrap_external",
                        "_frozen_importlib_external",
                    )):
                return _importer_listdir(*args, **kwargs)
        except (ValueError, AttributeError):
            pass
        forbidden()
    _posix.listdir = _guarded_posix_listdir
"""


class OfflineScopePosixAliasTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-scope-posix-lab-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "sitecustomize.py").write_text(
            _POSIX_ALIAS_TRIPWIRE, encoding="utf-8"
        )
        (self.root / "synthetic-private.txt").write_text(
            "fictional-only-private-marker", encoding="utf-8"
        )
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_REPO / "src"), str(_REPO),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

    def fingerprint(self):
        return {
            str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*") if path.is_file()
        }

    def run_child(self, program):
        return subprocess.run(
            [sys.executable, "-B", "-c", program], cwd=self.root,
            env=self.env, capture_output=True, check=False, timeout=15,
        )

    def test_direct_native_alias_calls_do_not_bypass_public_os_guards(self):
        try:
            import posix
        except ImportError:
            self.skipTest("Direct posix extension only exists on POSIX")
        statements = (
            ("open", 'posix.open("synthetic-private.txt", os.O_RDONLY)'),
            ("read", 'posix.read(0, 1)'),
            ("write", 'posix.write(1, b"synthetic")'),
            ("listdir", 'posix.listdir(".")'),
            ("scandir", 'posix.scandir(".")'),
            ("dup", 'posix.dup(0)'),
            ("dup2", 'posix.dup2(0, 7)'),
            ("fork", 'posix.fork()'),
            ("posix_spawn", 'posix.posix_spawn("/bin/true", ["/bin/true"], {})'),
        )
        before = self.fingerprint()
        for name, statement in statements:
            if not hasattr(posix, name):
                continue
            with self.subTest(name=name):
                program = (
                    "import os, posix\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('FALSE_REVIEW_ONLY')\n"
                )
                result = self.run_child(program)
                self.assertEqual(result.returncode, 92, name)
                self.assertEqual(result.stdout, b"", name)
                self.assertEqual(result.stderr, b"", name)
                self.assertEqual(self.fingerprint(), before, name)

    def test_authentic_offline_cli_stays_review_only_or_hold(self):
        cases = (
            (b'{"arguments":[["synthetic",1.25]]}', "REVIEW_ONLY", 3),
            (b'{"arguments":[["synthetic",NaN]]}', "HOLD", 2),
        )
        before = self.fingerprint()
        cli = _SCRIPTS / "review_scope_finite_number_offline.py"
        self.assertTrue(cli.is_file())
        for payload, status, code in cases:
            with self.subTest(status=status):
                result = subprocess.run(
                    [sys.executable, "-B", str(cli)], cwd=self.root,
                    env=self.env, input=payload, capture_output=True,
                    check=False, timeout=15,
                )
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], status)
                for flag in _FLAGS:
                    self.assertIs(receipt[flag], False, flag)
                self.assertEqual(self.fingerprint(), before)
        exporter = _SCRIPTS / "export_scope_capability_registry_offline.py"
        self.assertTrue(exporter.is_file())
        result = subprocess.run(
            [sys.executable, "-B", str(exporter)], cwd=self.root,
            env=self.env, capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertIn("capabilities", json.loads(result.stdout))
        self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
