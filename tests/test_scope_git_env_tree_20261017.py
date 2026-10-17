"""Adversarial synthetic Git tree mode proof. Never touches a real Git tree."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

FILE = Path(__file__).resolve().parents[1] / "scripts/check_scope_git_env_tree_20261017.py"
spec = importlib.util.spec_from_file_location("test_owned_tree", FILE)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

PATHS = sorted(guard.OWNED)
OID = b"a" * 40


def delta(paths=PATHS, status=b"A"):
    return b"".join(status + b"\0" + p.encode() + b"\0" for p in paths)


def tree(paths=PATHS, mode=b"100644", kind=b"blob", oid=OID):
    return b"".join(mode + b" " + kind + b" " + oid
                    + b"\t" + p.encode() + b"\0" for p in paths)


class OfflineTreeModesTests(unittest.TestCase):
    def test_all_five_new_regular_git_blobs_pass(self):
        self.assertEqual(len(guard.OWNED), 6)
        self.assertTrue(guard.safe_tree(tree(), delta()))

    def test_symlinks_executables_gitlinks_and_mismatched_objects_hold(self):
        for mode, kind in (
            (b"120000", b"blob"), (b"100755", b"blob"),
            (b"160000", b"commit"), (b"040000", b"tree"),
            (b"100644", b"commit"), (b"100664", b"blob"),
        ):
            with self.subTest(mode=mode, kind=kind):
                self.assertFalse(guard.safe_tree(tree(mode=mode, kind=kind), delta()))

    def test_diff_must_be_exactly_new_owned_files(self):
        self.assertTrue(guard.parse_additions(delta()) == guard.OWNED)
        cases = (
            delta()[:-1],
            delta() + delta()[:20],
            delta(PATHS[:-1]),
            delta(PATHS + ["src/lightup/scope.py"]),
            delta(status=b"M"),
            delta() + b"A\0src/lightup/scope.py\0",
            delta() + b" " * 9000,
            delta().replace(b"scripts", b"scr\xffpts"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:65]):
                self.assertIsNone(guard.parse_additions(raw))
                self.assertFalse(guard.safe_tree(tree(), raw))

    def test_tree_metadata_must_be_exact_and_unique(self):
        valid = tree()
        bad = (
            valid[:-1],
            valid + valid,
            tree(oid=b"g" * 40),
            tree(oid=b"a" * 64),
            tree(paths=PATHS[:-1]),
            tree(paths=PATHS[:-1] + [PATHS[-2]]),
            tree().replace(b"scripts", b"scr\xffpts"),
            valid + b"\0" * 18000,
        )
        for raw in bad:
            with self.subTest(raw=raw[:65]):
                self.assertFalse(guard.safe_tree(raw, delta()))

    def test_main_exact_push_and_tampered_modes(self):
        from subprocess import CompletedProcess
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        sha = "a" * 40
        event = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.BRANCH,
            "GITHUB_SHA": sha,
        }
        expected = {
            "status": b"",
            "rev-parse": sha.encode() + b"\n",
            "merge-base": b"",
            "diff": delta(),
            "ls-tree": tree(),
        }
        def fake_git(*argv):
            name = argv[0]
            return CompletedProcess(argv, 0, expected[name], b"")
        with patch.object(guard, "git", side_effect=fake_git):
            with patch.dict(guard.os.environ, event, clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 0)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=PASS")
            with patch.dict(guard.os.environ, dict(event, GITHUB_SHA="b" * 40), clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")
            with patch.dict(guard.os.environ, dict(event, GIT_DIR="/fake"), clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")
            expected["ls-tree"] = tree(mode=b"120000")
            with patch.dict(guard.os.environ, event, clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")

    def test_no_reusing_other_worker_paths(self):
        for item in ("src/lightup/scope.py", "tests/test_scope.py",
                     "scripts/check_scope_literal_branch_20261016.py"):
            with self.subTest(path=item):
                self.assertIsNone(guard.parse_additions(
                    delta(PATHS[:-1] + [item])
                ))


if __name__ == "__main__":
    unittest.main()
