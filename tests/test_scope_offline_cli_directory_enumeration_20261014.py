"""No directory enumeration in the synthetic offline scope review CLI canary.

Python-only independent test instrumentation, NEVER OS sandbox or authority.
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


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)
# Python executes sitecustomize before the actual CLI's imports. All
# directory enumeration variants terminate before enumerating host entries.
# Deliberately independent of production and other scope owner branches.
_DIRECTORY_TRIPWIRE = _TRIPWIRE + """
import glob

for name in ("listdir", "scandir", "walk", "fwalk"):
    if hasattr(os, name):
        setattr(os, name, forbidden)
for name in ("iterdir", "glob", "rglob", "walk"):
    if hasattr(pathlib.Path, name):
        setattr(pathlib.Path, name, forbidden)
for name in ("glob", "iglob"):
    if hasattr(glob, name):
        setattr(glob, name, forbidden)
"""


class OfflineScopeDirectoryEnumerationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-scope-dir-lab-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "sitecustomize.py").write_text(
            _DIRECTORY_TRIPWIRE, encoding="utf-8"
        )
        (self.root / "synthetic-private-marker.txt").write_bytes(
            b"fictional-private-tenant-marker"
        )
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_ROOT / "src"), str(_ROOT),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

    def fingerprint(self):
        return {
            str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*") if path.is_file()
        }

    def test_directory_enumeration_attempts_cannot_be_swallowed(self):
        # All operations point exclusively to disposable synthetic workspace.
        # They are intercepted before any directory data is returned.
        statements = (
            ("listdir", 'os.listdir(".")'),
            ("scandir", 'os.scandir(".")'),
            ("os_walk", 'next(os.walk("."))'),
            ("path_iterdir", 'list(pathlib.Path(".").iterdir())'),
            ("path_glob", 'list(pathlib.Path(".").glob("*"))'),
            ("path_rglob", 'list(pathlib.Path(".").rglob("*"))'),
            ("glob", 'glob.glob("*")'),
            ("iglob", 'next(glob.iglob("*"))'),
        )
        before = self.fingerprint()
        for name, statement in statements:
            with self.subTest(name=name):
                program = (
                    "import os, pathlib, glob\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_DIRECTORY_DISCLOSURE')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, name)
                self.assertEqual(proc.stdout, b"", name)
                self.assertEqual(proc.stderr, b"", name)
                self.assertEqual(self.fingerprint(), before, name)

    def test_actual_offline_scope_commands_remain_non_authorizing(self):
        cases = (
            (b'{"arguments":[["synthetic",1.25]]}', 3, "REVIEW_ONLY"),
            (b'{"arguments":[["synthetic",NaN]]}', 2, "HOLD"),
        )
        before = self.fingerprint()
        cli = _SCRIPTS / "review_scope_finite_number_offline.py"
        self.assertTrue(cli.is_file())
        for payload, expected_exit, status in cases:
            with self.subTest(status=status):
                proc = subprocess.run(
                    [sys.executable, "-B", str(cli)], cwd=self.root,
                    env=self.env, input=payload, capture_output=True,
                    check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, expected_exit, proc.stderr)
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(len(proc.stdout.splitlines()), 1)
                receipt = json.loads(proc.stdout)
                self.assertEqual(receipt["status"], status)
                for field in _FLAGS:
                    self.assertIs(receipt[field], False, field)
                self.assertEqual(self.fingerprint(), before)
        exporter = _SCRIPTS / "export_scope_capability_registry_offline.py"
        self.assertTrue(exporter.is_file())
        proc = subprocess.run(
            [sys.executable, "-B", str(exporter)], cwd=self.root,
            env=self.env, capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(proc.stderr, b"")
        self.assertIn("capabilities", json.loads(proc.stdout))
        self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
