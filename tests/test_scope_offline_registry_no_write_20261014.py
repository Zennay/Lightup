"""Hermetic zero-write, zero-SQLite attempt tests of real offline review CLIs.

Hooks are Python-level test tripwires (not OS security sandboxing).
All temporary manifest fixture creation happens in parent before hooks.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lightup.capabilities import get_capabilities
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_MARKER = "__LIGHTUP_OFFLINE_WRITE_ATTEMPT__"
_NON_AUTH = ("authorization_verified", "permit_issued", "execution_enabled",
             "merge_approved", "release_approved")
_CHILD = r"""
import builtins
import os
import pathlib
import runpy
import sqlite3
import sys

sys.dont_write_bytecode = True

def deny(*args, **kwargs):
    sys.stderr.write("__LIGHTUP_OFFLINE_WRITE_ATTEMPT__\n")
    raise RuntimeError("offline review attempted persistent state mutation")

_real_builtin_open = builtins.open
_real_os_open = os.open
_real_path_open = pathlib.Path.open

def checked_open(path, mode="r", *args, **kwargs):
    if type(mode) is not str or any(ch in mode for ch in "wax+"):
        return deny()
    return _real_builtin_open(path, mode, *args, **kwargs)

def checked_os_open(path, flags, *args, **kwargs):
    if type(flags) is not int or flags & (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    ):
        return deny()
    return _real_os_open(path, flags, *args, **kwargs)

def checked_path_open(path, mode="r", *args, **kwargs):
    if type(mode) is not str or any(ch in mode for ch in "wax+"):
        return deny()
    return _real_path_open(path, mode, *args, **kwargs)

builtins.open = checked_open
os.open = checked_os_open
pathlib.Path.open = checked_path_open
pathlib.Path.write_text = deny
pathlib.Path.write_bytes = deny
pathlib.Path.mkdir = deny
pathlib.Path.unlink = deny
pathlib.Path.rename = deny
pathlib.Path.replace = deny
os.mkdir = deny
os.makedirs = deny
os.rename = deny
os.replace = deny
os.remove = deny
os.unlink = deny
sqlite3.connect = deny

script = sys.argv[1]
arguments = sys.argv[2:]
sys.path.insert(0, os.path.dirname(script))
sys.argv = [script, *arguments]
runpy.run_path(script, run_name="__main__")
"""


def run_without_writes(script: str, *args: object) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, "-B", "-c", _CHILD, str(_SCRIPTS / script), *map(str, args)],
        text=True, capture_output=True, timeout=15,
    )
    if _MARKER in proc.stderr:
        raise AssertionError(f"offline CLI attempted a write/SQLite action: {script}")
    return proc


class OfflineNoMutationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.canonical = snapshot_manifest(get_capabilities())
        obj = json.loads(self.canonical)
        obj["capabilities"][0]["requires_explicit_activation"] = False
        self.changed = json.dumps(obj, separators=(",", ":")).encode()

    def store_fixtures(self, folder, *raw_items):
        filenames = []
        for index, raw in enumerate(raw_items):
            path = Path(folder) / f"manifest-{index}.json"
            path.write_bytes(raw)
            filenames.append(path)
        return filenames

    def assert_no_authority(self, result):
        receipt = json.loads(result.stdout)
        for field in _NON_AUTH:
            self.assertIs(receipt[field], False, field)
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        return receipt

    def test_source_export_no_write_or_sqlite(self):
        proc = run_without_writes("export_scope_capability_registry_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), json.loads(self.canonical))

    def test_pairwise_equal_no_write_or_sqlite(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.canonical)
            proc = run_without_writes("review_scope_capability_registry_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertEqual(self.assert_no_authority(proc)["status"], "REVIEW_ONLY")

    def test_pairwise_changed_no_write_or_sqlite(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.changed)
            proc = run_without_writes("review_scope_capability_registry_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(self.assert_no_authority(proc)["status"], "HOLD")

    def test_historical_equal_no_write_or_sqlite(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.canonical)
            proc = run_without_writes("review_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assert_no_authority(proc)

    def test_history_change_and_revert_stays_hold_without_write(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.changed, self.canonical)
            proc = run_without_writes("review_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(len(self.assert_no_authority(proc)["transitions"]), 2)

    def test_local_checkout_history_equal_no_write(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.canonical)
            proc = run_without_writes("review_scope_history_against_checkout_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assert_no_authority(proc)

    def test_local_checkout_history_stale_holds_without_write(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.changed, self.changed)
            proc = run_without_writes("review_scope_history_against_checkout_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assert_no_authority(proc)

    def test_markdown_history_equal_no_write(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.canonical)
            proc = run_without_writes("render_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertIn("**Authority: NONE.**", proc.stdout)

    def test_markdown_history_drift_holds_without_write(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.store_fixtures(folder, self.canonical, self.changed)
            proc = run_without_writes("render_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("**Authority: NONE.**", proc.stdout)

    def test_incubation_posture_no_write(self):
        proc = run_without_writes("review_scope_incubation_registry_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assert_no_authority(proc)

    def test_incubation_field_diagnostics_no_write_or_sqlite(self):
        proc = run_without_writes("review_scope_incubation_fields_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["changed_fields"], {})

    def test_incubation_field_diagnostics_denies_args_without_write(self):
        for arg in ("--activate", "https://synthetic.invalid"):
            with self.subTest(arg=arg):
                proc = run_without_writes("review_scope_incubation_fields_offline.py", arg)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assert_no_authority(proc)

    def test_incubation_catalog_no_write(self):
        proc = run_without_writes("review_scope_incubation_catalog_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assert_no_authority(proc)

    def test_incubation_catalog_deny_activation_arg_no_write(self):
        proc = run_without_writes("review_scope_incubation_catalog_offline.py", "--activate")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assert_no_authority(proc)

    def test_missing_baseline_denies_without_write(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "absent"
            proc = run_without_writes("review_scope_capability_registry_offline.py", path, path)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assert_no_authority(proc)

    def test_all_zero_argument_invalid_paths_never_success_or_write(self):
        for script in (
            "review_scope_capability_registry_offline.py",
            "review_scope_registry_history_offline.py",
            "review_scope_history_against_checkout_offline.py",
            "render_scope_registry_history_offline.py",
        ):
            with self.subTest(script=script):
                proc = run_without_writes(script)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                if script.startswith("render_"):
                    self.assertIn("**Authority: NONE.**", proc.stdout)
                else:
                    self.assert_no_authority(proc)


if __name__ == "__main__":
    unittest.main()
