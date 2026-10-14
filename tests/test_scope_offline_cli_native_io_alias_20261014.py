"""No direct _io.open bypass of the synthetic offline scope CLI read allowlist.

Regression-only Python subprocess tripwire (#1410). NOT an OS sandbox, a
production authorization gate or proof about arbitrary C/native syscalls.
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
# Installed before a real CLI starts. Preserve importlib's separate
# _io.open_code: restricting Python source import is NOT this test's purpose.
# The distinct _io.open alias otherwise bypasses the public io.open wrapper.
_NATIVE_ALIAS_TRIPWIRE = _TRIPWIRE + """
import _io

# Python itself reads the explicitly invoked .py entrypoint through
# _io.open(..., "rb") before it can run the CLI. Grant only that *one*
# exact parent-selected code path, never arbitrary code/manifest aliases.
_TRUSTED_BOOTSTRAP_SCRIPT = os.environ.get("LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT", "")

def checked_direct_io_open(path, mode="r", *args, **kwargs):
    if (type(path) is str and path == _TRUSTED_BOOTSTRAP_SCRIPT
            and _TRUSTED_BOOTSTRAP_SCRIPT and mode == "rb"
            and not args and not kwargs):
        return _real_io_open(path, mode)
    if type(path) not in (str, type(pathlib.Path())):
        forbidden()
    if kwargs.get("opener") is not None or (len(args) >= 6 and args[5] is not None):
        forbidden()
    return checked_io_open(path, mode, *args, **kwargs)

_io.open = checked_direct_io_open
"""


class OfflineScopeNativeIOAliasTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-scope-native-io-lab-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sitecustomize.py").write_text(
            _NATIVE_ALIAS_TRIPWIRE, encoding="utf-8"
        )
        (self.root / "synthetic-private.txt").write_text(
            "synthetic-only-not-a-secret", encoding="utf-8"
        )
        (self.root / "baseline.json").write_text(
            '{"synthetic":"manifest"}', encoding="utf-8"
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

    def run_child(self, program: str):
        return subprocess.run(
            [sys.executable, "-B", "-c", program], cwd=self.root,
            env=self.env, capture_output=True, check=False, timeout=15,
        )

    def test_direct_native_alias_reads_abort_before_a_decoy_is_touched(self):
        statements = (
            ("local_decoy", '_io.open("synthetic-private.txt", "rb").read(1)'),
            ("inherited_stdin", '_io.open(0, "rb", closefd=False).read(1)'),
            ("foreign_opener",
             '_io.open("baseline.json", "rb", opener=lambda _path, _flags: 0).read(1)'),
            ("positional_opener",
             '_io.open("baseline.json", "rb", -1, None, None, None, True, '
             'lambda _path, _flags: 0).read(1)'),
            ("custom_pathlike", '_io.open(ExecutablePath(), "rb").read(1)'),
        )
        before = self.fingerprint()
        for name, statement in statements:
            with self.subTest(name=name):
                program = (
                    "import _io\n"
                    "class ExecutablePath:\n"
                    "    def __fspath__(self):\n"
                    "        print('ALIAS_CALLBACK_EXECUTED')\n"
                    "        return 'baseline.json'\n"
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

    def test_actual_opt_in_review_and_export_remain_non_authorizing(self):
        cases = (
            ("review_scope_finite_number_offline.py",
             b'{"arguments":[["synthetic",1.25]]}', 3, "REVIEW_ONLY"),
            ("review_scope_finite_number_offline.py",
             b'{"arguments":[["synthetic",NaN]]}', 2, "HOLD"),
        )
        before = self.fingerprint()
        for script, payload, expected_code, expected_status in cases:
            with self.subTest(script=script, status=expected_status):
                result = subprocess.run(
                    [sys.executable, "-B", str(_SCRIPTS / script)],
                    cwd=self.root, env=dict(self.env, LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT=str(_SCRIPTS / script)), input=payload,
                    capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(result.returncode, expected_code, result.stderr)
                self.assertEqual(result.stderr, b"")
                data = json.loads(result.stdout)
                self.assertEqual(data["status"], expected_status)
                for flag in _FLAGS:
                    self.assertIs(data[flag], False)
                self.assertEqual(self.fingerprint(), before)
        exporter = subprocess.run(
            [sys.executable, "-B",
             str(_SCRIPTS / "export_scope_capability_registry_offline.py")],
            cwd=self.root, env=dict(self.env, LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT=str(_SCRIPTS / "export_scope_capability_registry_offline.py")), capture_output=True,
            check=False, timeout=15,
        )
        self.assertEqual(exporter.returncode, 3, exporter.stderr)
        self.assertEqual(exporter.stderr, b"")
        exported = json.loads(exporter.stdout)
        self.assertIn("capabilities", exported)
        self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
