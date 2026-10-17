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

    def test_exact_worktree_bytes_must_match_owned_head_tree(self):
        """Independent synthetic Git blob IDs without touching a real remote."""
        import hashlib
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix=".scope-blob-fixture-", dir=ROOT) as home:
            root = Path(home)
            refs = {}
            for path in PATHS:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                content = b"synthetic-offline-blob:" + path.encode("ascii")
                target.write_bytes(content)
                refs[path] = hashlib.sha1(
                    b"blob " + str(len(content)).encode("ascii") + b"\0" + content
                ).hexdigest().encode("ascii")
            records = b"".join(
                b"100644 blob " + refs[path] + b"\t" + path.encode("ascii") + b"\0"
                for path in PATHS
            )
            self.assertTrue(guard.worktree_matches_tree(records, changes(), root))
            victim = root / PATHS[-1]
            victim.write_bytes(b"modified-and-not-staged")
            self.assertFalse(guard.worktree_matches_tree(records, changes(), root))
            victim.unlink()
            self.assertFalse(guard.worktree_matches_tree(records, changes(), root))
            victim.symlink_to(root / PATHS[0])
            self.assertFalse(guard.worktree_matches_tree(records, changes(), root))
            victim.unlink()
            victim.write_bytes(b"x" * (guard.MAX_OWNED_BLOB_BYTES + 1))
            self.assertFalse(guard.worktree_matches_tree(records, changes(), root))

    def test_worktree_blob_proof_fails_on_tree_or_delta_tampering(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix=".scope-blob-negative-", dir=ROOT) as home:
            root = Path(home)
            self.assertFalse(guard.worktree_matches_tree(tree(), changes(), root))
            self.assertFalse(guard.worktree_matches_tree(tree(mode="120000"), changes(), root))
            self.assertFalse(guard.worktree_matches_tree(tree(), changes()[:-1], root))

    def test_missing_added_tree_entry_is_hold(self):
        self.assertFalse(guard.safe_tree(tree(PATHS[:-1]), changes()))
        self.assertFalse(guard.safe_tree(tree(), changes(PATHS[:-1])))

    def test_foreign_or_edited_status_cannot_pass_tree_verification(self):
        bad_delta = changes() + b"M\0src/lightup/scope.py\0"
        self.assertFalse(guard.safe_tree(tree(), bad_delta))


if __name__ == "__main__":
    unittest.main()
