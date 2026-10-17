"""Git tree type checks for independent offline scope-review branch.

Only synthetic raw-tree bytes; tests never mutate Git state or real targets.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_scope_literal_branch_20261016.py"
spec = importlib.util.spec_from_file_location("scope_git_modes", SCRIPT)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

PATHS = tuple(sorted(guard.OWNED_EXACT | {
    "tests/test_scope_literal_git_modes_20261016.py",
}))
OID = b"a" * 40


def changes(paths=PATHS):
    return b"".join(b"A\0" + p.encode("ascii") + b"\0" for p in paths)


def tree(paths=PATHS, mode="100644", kind="blob", oid=OID):
    return b"".join(
        mode.encode("ascii") + b" " + kind.encode("ascii") + b" "
        + oid + b"\t" + p.encode("ascii") + b"\0"
        for p in paths
    )


class TreeModeFenceTests(unittest.TestCase):
    def test_regular_additive_blobs_only(self):
        self.assertTrue(guard.safe_tree(tree(), changes()))

    def test_symlink_gitlink_executable_or_tree_never_pass(self):
        for mode, kind in (
            ("120000", "blob"), ("160000", "commit"),
            ("100755", "blob"), ("040000", "tree"),
            ("100664", "blob"), ("100644", "commit"),
        ):
            with self.subTest(mode=mode, kind=kind):
                self.assertFalse(guard.safe_tree(tree(mode=mode, kind=kind), changes()))

    def test_broken_tree_metadata_and_duplicate_paths_hold(self):
        valid = tree()
        self.assertFalse(guard.safe_tree(b"", changes()))
        self.assertFalse(guard.safe_tree(valid[:-1], changes()))
        self.assertFalse(guard.safe_tree(valid + valid, changes()))
        self.assertFalse(guard.safe_tree(valid.replace(OID, b"z" * 40), changes()))
        self.assertFalse(guard.safe_tree(valid.replace(b"scripts", b"scr\xffpts"), changes()))
        self.assertFalse(guard.safe_tree(valid + b"0" * 16385, changes()))

    def test_missing_added_tree_entry_is_hold(self):
        self.assertFalse(guard.safe_tree(tree(PATHS[:-1]), changes()))
        self.assertFalse(guard.safe_tree(tree(), changes(PATHS[:-1])))

    def test_foreign_or_edited_status_cannot_pass_tree_verification(self):
        bad_delta = changes() + b"M\0src/lightup/scope.py\0"
        self.assertFalse(guard.safe_tree(tree(), bad_delta))


if __name__ == "__main__":
    unittest.main()
