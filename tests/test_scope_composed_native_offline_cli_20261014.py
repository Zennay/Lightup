"""Compose actual scope reviewer CLI entrypoints under all offline I/O tripwires.

Source-only Python-level synthetic integration test (#1414). Never claims
kernel sandbox, real customer consent, grant issuance or production authority.
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

from test_scope_offline_cli_native_io_alias_20261014 import _NATIVE_ALIAS_TRIPWIRE


_REPO = Path(__file__).resolve().parents[1]
_SCRIPTS = _REPO / "scripts"
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


class ComposedNativeOfflineScopeFleetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-composed-io-lab-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sitecustomize.py").write_text(
            _NATIVE_ALIAS_TRIPWIRE, encoding="utf-8"
        )
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_REPO / "src"), str(_REPO),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

        initial = self.run_cli("export_scope_capability_registry_offline.py")
        self.assertEqual(initial.returncode, 3, initial.stderr)
        self.assertEqual(initial.stderr, b"")
        manifest = json.loads(initial.stdout)
        self.assertIn("capabilities", manifest)
        self.assertTrue(manifest["capabilities"])
        self.baseline = self.root / "baseline.json"
        self.baseline.write_bytes(initial.stdout)
        # Distinct physical file identity is an intentional reviewer contract.
        self.equal = self.root / "equal-but-distinct.json"
        self.equal.write_bytes(initial.stdout)
        manifest["capabilities"][0]["requires_explicit_activation"] = False
        self.changed = self.root / "changed.json"
        self.changed.write_text(json.dumps(manifest), encoding="utf-8")

    def run_cli(self, name: str, *args: Path | str, stdin: bytes = b""):
        executable = _SCRIPTS / name
        self.assertTrue(executable.is_file(), name)
        env = dict(
            self.env,
            LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT=str(executable),
            LIGHTUP_SCOPE_SOURCE_ROOT=str(_REPO / "src" / "lightup"),
            LIGHTUP_SCOPE_SCRIPTS_ROOT=str(_SCRIPTS),
        )
        return subprocess.run(
            [sys.executable, "-B", str(executable), *map(str, args)],
            cwd=self.root, env=env, input=stdin,
            capture_output=True, check=False, timeout=15,
        )

    def fingerprint(self) -> dict[str, str]:
        return {
            str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.root.rglob("*") if p.is_file()
        }

    def check_receipt(self, result, expected: str, markdown: bool = False):
        self.assertEqual(result.returncode, 3 if expected == "REVIEW_ONLY" else 2)
        self.assertEqual(result.stderr, b"")
        self.assertTrue(result.stdout)
        if markdown:
            message = result.stdout.decode("utf-8")
            self.assertIn(expected, message)
            self.assertIn("**Authority: NONE.**", message)
            self.assertNotIn("execution_enabled: true", message)
            return
        self.assertEqual(len(result.stdout.splitlines()), 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], expected)
        for flag in _FLAGS:
            self.assertIs(data[flag], False, flag)

    def test_seven_actual_reviewers_plus_exporter_have_no_native_io_bypass(self):
        controls = (
            ("review_scope_capability_registry_offline.py", (self.baseline, self.equal), b"", False),
            ("review_scope_registry_history_offline.py", (self.baseline, self.equal), b"", False),
            ("review_scope_history_against_checkout_offline.py", (self.baseline, self.equal), b"", False),
            ("render_scope_registry_history_offline.py", (self.baseline, self.equal), b"", True),
            ("review_scope_incubation_registry_offline.py", (), b"", False),
            ("review_scope_incubation_catalog_offline.py", (), b"", False),
            ("review_scope_finite_number_offline.py", (), b'{"arguments":[["synthetic",1.5]]}', False),
        )
        before = self.fingerprint()
        for name, args, payload, markdown in controls:
            with self.subTest(script=name):
                result = self.run_cli(name, *args, stdin=payload)
                self.check_receipt(result, "REVIEW_ONLY", markdown=markdown)
                self.assertEqual(self.fingerprint(), before, name)
        # The eighth real entrypoint is the exporter in fixture setUp.
        self.assertEqual(self.fingerprint(), before)

    def test_invalid_snapshots_hold_under_composed_fleet_guard(self):
        controls = (
            ("review_scope_capability_registry_offline.py", (self.baseline, self.changed), b"", False),
            ("review_scope_registry_history_offline.py", (self.baseline, self.changed), b"", False),
            ("review_scope_history_against_checkout_offline.py", (self.changed, self.changed), b"", False),
            ("render_scope_registry_history_offline.py", (self.baseline, self.changed), b"", True),
            ("review_scope_incubation_registry_offline.py", ("--activate",), b"", False),
            ("review_scope_incubation_catalog_offline.py", ("--activate",), b"", False),
            ("review_scope_finite_number_offline.py", (), b'{"arguments":[["synthetic",NaN]]}', False),
        )
        before = self.fingerprint()
        for name, args, payload, markdown in controls:
            with self.subTest(script=name):
                result = self.run_cli(name, *args, stdin=payload)
                self.check_receipt(result, "HOLD", markdown=markdown)
                self.assertEqual(self.fingerprint(), before, name)


    def test_code_named_decoy_is_not_trusted_as_import(self):
        # A Python-looking basename outside frozen interpreter/project code
        # roots must never become an allowed native alias read.
        decoy = self.root / "synthetic-private.py"
        decoy.write_text("# synthetic-only never-read decoy", encoding="utf-8")
        before = self.fingerprint()
        env = dict(
            self.env,
            LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT=str(
                _SCRIPTS / "review_scope_finite_number_offline.py"),
            LIGHTUP_SCOPE_SOURCE_ROOT=str(_REPO / "src" / "lightup"),
            LIGHTUP_SCOPE_SCRIPTS_ROOT=str(_SCRIPTS),
        )
        program = (
            "import _io\n"
            "try:\n"
            "    _io.open('synthetic-private.py', 'rb').read(1)\n"
            "except BaseException:\n"
            "    pass\n"
            "print('FALSE_REVIEW_ONLY')\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", program], cwd=self.root,
            env=env, capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(result.returncode, 92)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
