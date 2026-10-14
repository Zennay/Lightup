"""Pin synthetic manifest descriptor identity after os.open; no live authority.

Python-only offline scope review acceptance (#1418), not an OS sandbox.
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
# Installed at Python startup in an isolated synthetic subprocess before
# the real opt-in scope-review CLI imports its own domain modules.
_INODE_TRIPWIRE = _TRIPWIRE + """
import stat as _stat

# This cannot pin *content*. It fixes inode identity only and detects a
# substituted FD returned after a separately accepted manifest pathname.
_PINNED_INODES = {}
for _p in _READ_ALLOWLIST:
    try:
        _meta = os.lstat(_p)
    except FileNotFoundError:
        continue
    if _stat.S_ISREG(_meta.st_mode):
        _PINNED_INODES[_p] = (_meta.st_dev, _meta.st_ino)
_BASE_GUARDED_OS_OPEN = os.open

def pinned_os_open(path, flags, *args, **kwargs):
    if type(path) not in (str, _CANONICAL_PATH_TYPE):
        forbidden()
    _raw = os.fspath(path)
    if type(_raw) is not str:
        forbidden()
    try:
        _canonical = os.path.realpath(_raw)
        # Refuse symlinks, relative traversals, and alternate path names.
        # The actual CLI provides absolute synthetic manifest paths.
        if (os.path.abspath(_raw) != _canonical
                or _canonical not in _PINNED_INODES):
            forbidden()
    except (TypeError, ValueError, OSError):
        forbidden()
    _fd = _BASE_GUARDED_OS_OPEN(path, flags, *args, **kwargs)
    try:
        _opened = os.fstat(_fd)
        if (not _stat.S_ISREG(_opened.st_mode)
                or (_opened.st_dev, _opened.st_ino) != _PINNED_INODES[_canonical]):
            forbidden()
    except (TypeError, ValueError, OSError):
        forbidden()
    return _fd

os.open = pinned_os_open
"""


class OfflineScopeManifestInodeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-scope-inode-lab-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "sitecustomize.py").write_text(
            _INODE_TRIPWIRE, encoding="utf-8"
        )
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_ROOT / "src"), str(_ROOT),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

        exporter = self.run_script("export_scope_capability_registry_offline.py")
        self.assertEqual(exporter.returncode, 3, exporter.stderr)
        self.assertEqual(exporter.stderr, b"")
        payload = json.loads(exporter.stdout)
        self.assertIn("capabilities", payload)
        self.original = self.root / "baseline.json"
        self.original.write_bytes(exporter.stdout)
        self.equal = self.root / "equal-but-distinct.json"
        self.equal.write_bytes(exporter.stdout)
        payload["capabilities"][0]["requires_explicit_activation"] = False
        self.changed = self.root / "changed.json"
        self.changed.write_text(json.dumps(payload), encoding="utf-8")
        self.decoy = self.root / "synthetic-private.txt"
        self.decoy.write_text("fictional-never-read", encoding="utf-8")

    def run_script(self, name: str, *args: object, stdin: bytes = b""):
        self.assertTrue((_SCRIPTS / name).is_file())
        return subprocess.run(
            [sys.executable, "-B", str(_SCRIPTS / name), *map(str, args)],
            cwd=self.root, env=self.env, input=stdin, capture_output=True,
            check=False, timeout=15,
        )

    def run_child(self, source: str):
        return subprocess.run(
            [sys.executable, "-B", "-c", source],
            cwd=self.root, env=self.env, capture_output=True,
            check=False, timeout=15,
        )

    def fingerprint(self):
        return {
            str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*") if path.is_file()
        }

    def assert_receipt(self, proc, status):
        self.assertEqual(proc.returncode, 3 if status == "REVIEW_ONLY" else 2,
                         proc.stderr)
        self.assertEqual(proc.stderr, b"")
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], status)
        for field in _FLAGS:
            self.assertIs(data[field], False, field)

    def test_real_registry_and_finite_number_cli_keep_read_only_semantics(self):
        before = self.fingerprint()
        self.assert_receipt(self.run_script(
            "review_scope_capability_registry_offline.py",
            self.original, self.equal,
        ), "REVIEW_ONLY")
        self.assertEqual(self.fingerprint(), before)
        self.assert_receipt(self.run_script(
            "review_scope_capability_registry_offline.py",
            self.original, self.changed,
        ), "HOLD")
        self.assertEqual(self.fingerprint(), before)
        self.assert_receipt(self.run_script(
            "review_scope_finite_number_offline.py",
            stdin=b'{"arguments":[["synthetic",1.5]]}',
        ), "REVIEW_ONLY")
        self.assert_receipt(self.run_script(
            "review_scope_finite_number_offline.py",
            stdin=b'{"arguments":[["synthetic",NaN]]}',
        ), "HOLD")
        self.assertEqual(self.fingerprint(), before)

    def test_canonical_pinned_manifest_descriptor_still_works(self):
        before = self.fingerprint()
        program = (
            "import os\n"
            "fd = os.open('baseline.json', os.O_RDONLY)\n"
            "assert os.read(fd, 1) == b'{' \n"
            "os.close(fd)\n"
            "print('SYNTHETIC_READ_ONLY_OK')\n"
        )
        proc = self.run_child(program)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, b"SYNTHETIC_READ_ONLY_OK\n")
        self.assertEqual(proc.stderr, b"")
        self.assertEqual(self.fingerprint(), before)

    def test_symlink_alias_and_substituted_descriptor_abort_before_content(self):
        alias = self.root / "synthetic-alias.json"
        alias.symlink_to(self.original.name)
        before = self.fingerprint()
        attempts = (
            ("symlink_alias",
             "import os\nos.open('synthetic-alias.json', os.O_RDONLY)\n"),
            ("substituted_fd",
             "import os, sitecustomize as guard\n"
             "real = guard._real_os_open\n"
             "def swap(path, flags, *args, **kwargs):\n"
             "    return real('synthetic-private.txt', flags)\n"
             "guard._real_os_open = swap\n"
             "os.open('baseline.json', os.O_RDONLY)\n"),
        )
        for label, statement in attempts:
            with self.subTest(label=label):
                program = (
                    "try:\n" +
                    "".join("    " + line + "\n" for line in statement.splitlines()) +
                    "except BaseException:\n"
                    "    pass\n"
                    "print('FALSE_REVIEW_ONLY')\n"
                )
                # Python import statements in 'try' body are fine; all files
                # are synthetic and substitution opens without reading.
                proc = self.run_child(program)
                self.assertEqual(proc.returncode, 92, label)
                self.assertEqual(proc.stdout, b"", label)
                self.assertEqual(proc.stderr, b"", label)
                self.assertEqual(self.fingerprint(), before, label)


if __name__ == "__main__":
    unittest.main()
