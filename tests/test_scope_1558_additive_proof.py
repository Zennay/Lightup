"""Disposable synthetic Git fixtures for exact-additive scope #1558 guard."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.check_scope_1558_additive_proof import (
    InvalidOwnership, OWNED_FILES, validate_owned_changes,
)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, text=True, check=True, timeout=10,
    )
    return result.stdout.strip()


def initialize_fixture():
    directory = tempfile.TemporaryDirectory(prefix="fictional-scope1558-git-")
    root = Path(directory.name)
    git(root, "init", "-q")
    git(root, "config", "user.email", "fictional@example.invalid")
    git(root, "config", "user.name", "Fictional Scope Test")
    (root / "existing.txt").write_text("untouched", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "original")
    return directory, root, git(root, "rev-parse", "HEAD")


def add_all(root: Path):
    for path in OWNED_FILES:
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("synthetic only", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "add-only synthetic sources")


class Scope1558AddOnlyTests(unittest.TestCase):
    def test_ten_exact_new_files_pass(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            self.assertEqual(
                OWNED_FILES,
                validate_owned_changes(root, base, OWNED_FILES),
            )

    def test_modified_original_file_fails(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            (root / "existing.txt").write_text("modified", encoding="utf-8")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "violate source owner")
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, base, OWNED_FILES)

    def test_extra_foreign_file_fails(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            (root / "src" / "lightup" / "activation.py").write_text("foreign")
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "foreign source")
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, base, OWNED_FILES)

    def test_incomplete_set_fails(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            (root / "docs" / "scope-audit-anchor-auth-offline.md").unlink()
            git(root, "add", ".")
            git(root, "commit", "-q", "-m", "delete owned")
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, base, OWNED_FILES)

    def test_absent_base_fails(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, "f" * 40, OWNED_FILES)

    def test_bad_base_type_fails_without_git(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            for wrong in (None, "main", True, "X" * 40):
                with self.subTest(base=wrong):
                    with self.assertRaises(InvalidOwnership):
                        validate_owned_changes(root, wrong, OWNED_FILES)

    def test_noncanonical_path_owner_list_fails(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, base, frozenset({"../../unsafe"}))
            with self.assertRaises(InvalidOwnership):
                validate_owned_changes(root, base, {"files": "not frozen"})

    def test_no_shell_invocation_on_valid_fixture(self):
        context, root, base = initialize_fixture()
        with context:
            add_all(root)
            output = validate_owned_changes(root, base, OWNED_FILES)
            self.assertEqual(10, len(output))


if __name__ == "__main__":
    unittest.main()
