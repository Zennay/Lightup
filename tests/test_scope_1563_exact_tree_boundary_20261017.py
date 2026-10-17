"""Synthetic offline tests for the #1563 immutable ownership gate.

Creates only disposable local Git repositories; no remote or real asset access.
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "scope_1563_exact_tree_boundary_20261017.py"
spec = importlib.util.spec_from_file_location("scope_1563_exact_tree_gate", MODULE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ParseScopeOwnerRecordsTests(unittest.TestCase):
    def test_exact_new_paths(self):
        records = b"".join(
            b"A\0" + path.encode("ascii") + b"\0"
            for path in sorted(gate.ALLOWED_ADDED)
        )
        self.assertEqual(gate.parse_changes(records), gate.ALLOWED_ADDED)

    def test_every_owner_path_is_mandatory(self):
        records = b"".join(
            b"A\0" + path.encode("ascii") + b"\0"
            for path in sorted(gate.ALLOWED_ADDED)[:-1]
        )
        with self.assertRaises(gate.Hold):
            gate.parse_changes(records)

    def test_reject_existing_file_change_and_rename(self):
        for status in (b"M", b"D", b"R100", b"C100", b"X"):
            with self.subTest(status=status), self.assertRaises(gate.Hold):
                gate.parse_changes(status + b"\0" + next(iter(gate.ALLOWED_ADDED)).encode() + b"\0")

    def test_reject_duplicate_or_unowned_path(self):
        p = next(iter(gate.ALLOWED_ADDED)).encode("ascii")
        for data in (
            b"A\0" + p + b"\0A\0" + p + b"\0",
            b"A\0src/lightup/scope.py\0",
            b"A\0.github/workflows/other-worker.yml\0",
        ):
            with self.subTest(data=data), self.assertRaises(gate.Hold):
                gate.parse_changes(data)

    def test_reject_broken_utf8_alias_or_partial_records(self):
        for data in (
            b"",
            b"A\0a",
            b"A\0",
            b"A\0tests/\xc3\xa9vil.py\0",
            b"A\0../../src/lightup/scope.py\0",
        ):
            with self.subTest(data=data), self.assertRaises(gate.Hold):
                gate.parse_changes(data)


class TemporaryOwnerTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope-1563-tree-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self._git("init", "-q")
        self._write("README.md", "base")
        self._git("add", "README.md")
        self._git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base")
        self.base = self._git("rev-parse", "HEAD")
        self.original = gate.ORIGINAL_BASE
        gate.ORIGINAL_BASE = self.base
        self.addCleanup(setattr, gate, "ORIGINAL_BASE", self.original)

    def _git(self, *args):
        result = subprocess.run(
            ("git", *args), cwd=self.root, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        return result.stdout.decode("ascii").strip()

    def _write(self, name, content):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def _commit(self):
        self._git("add", "-A")
        self._git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "proposed")
        return self._git("rev-parse", "HEAD")

    def _build_owned(self):
        for name in gate.ALLOWED_ADDED:
            self._write(name, "synthetic fixture")
        return self._commit()

    def test_exact_additive_tree_is_review_only(self):
        head = self._build_owned()
        result = gate.inspect_exact_head(self.root, head)
        self.assertEqual(result["decision"], "REVIEW_ONLY")
        self.assertEqual(result["added_paths"], len(gate.ALLOWED_ADDED))
        self.assertEqual(result["authorization_granted"], "false")
        self.assertEqual(result["release_approved"], "false")

    def test_reject_source_change_even_with_all_expected_new_paths(self):
        self._write("README.md", "modified original file")
        head = self._build_owned()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)

    def test_reject_missing_file_or_wrong_exact_head(self):
        names = sorted(gate.ALLOWED_ADDED)
        for name in names[:-1]:
            self._write(name, "synthetic fixture")
        head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, self.base)

    def test_reject_symlink_in_owned_path(self):
        names = sorted(gate.ALLOWED_ADDED)
        for name in names[:-1]:
            self._write(name, "synthetic fixture")
        target = self.root / names[-1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(self.root / "README.md")
        head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)


if __name__ == "__main__":
    unittest.main()
