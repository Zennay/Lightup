"""Adversarial acceptance for the worker-only Git additivity fence."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_scope_literal_branch_20261016.py"
spec = importlib.util.spec_from_file_location("scope_owned_additive_proof", CHECKER)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def evidence(extra=()):
    values = [("A", path) for path in sorted(guard.OWNED_EXACT)]
    values.extend(extra)
    return b"".join(
        status.encode("ascii") + b"\0" + path.encode("ascii") + b"\0"
        for status, path in values
    )


class AdditiveOwnershipTests(unittest.TestCase):
    def test_exact_own_additions_are_allowed(self):
        self.assertTrue(guard.safe_diff(evidence((
            ("A", "tests/test_scope_literal_controls_20261016.py"),
            ("A", "tests/test_scope_literal_ownership_20261016.py"),
        ))))
        self.assertTrue(guard.safe_change("A", "tests/test_scope_literal_demo_20261016.py"))

    def test_existing_paths_and_other_workers_are_rejected(self):
        for status, name in (
            ("M", "src/lightup/scope.py"),
            ("D", "tests/test_scope.py"),
            ("M", "scripts/check_scope_literal_suite_20261016.py"),
            ("R100", "scripts/check_scope_literal_branch_20261016.py"),
            ("A", "src/lightup/activation.py"),
            ("A", "tests/test_scope_literal_demo_20261017.py"),
            ("A", "tests/test_scope_literal_demo_20261016.py/../../other"),
            ("A", ".github/workflows/lightup-ci.yml"),
            ("A", "docs/other-worker.md"),
        ):
            with self.subTest(status=status, name=name):
                self.assertFalse(guard.safe_change(status, name))
                self.assertFalse(guard.safe_diff(evidence(((status, name),))))

    def test_truncated_duplicate_or_unexpected_wire_is_hold(self):
        baseline = evidence()
        self.assertTrue(guard.safe_diff(baseline))
        self.assertFalse(guard.safe_diff(b""))
        self.assertFalse(guard.safe_diff(baseline[:-1]))
        self.assertFalse(guard.safe_diff(baseline + baseline[:25]))
        self.assertFalse(guard.safe_diff(baseline + b"A\0tests/test_scope_literal_x_20261016.py"))
        self.assertFalse(guard.safe_diff(baseline + b"M\0src/lightup/scope.py\0"))
        self.assertFalse(guard.safe_diff(baseline + b"A\0tests/test_scope_literal_x_20261016.py\0" * 2))
        self.assertFalse(guard.safe_diff(baseline.replace(b"scripts", b"scr\xffpts")))
        self.assertFalse(guard.safe_diff(baseline + b"x" * 16385))

    def test_worktree_must_be_proven_clean(self):
        # Origin/main additivity does not attest the files actually tested.
        # Git status porcelain -z must be exactly empty, not whitespace.
        from subprocess import CompletedProcess
        self.assertTrue(guard.clean_worktree_status(CompletedProcess(["git"], 0, b"", b"")))
        for raw in (
            b" M src/lightup/scope.py\0",
            b"M  scripts/check_scope_literal_branch_20261016.py\0",
            b"?? tests/untracked_payload.py\0",
            b"?? docs/fake.md\0",
            b"!! ignored.py\0",
            b" ",
        ):
            with self.subTest(status=raw):
                self.assertFalse(guard.clean_worktree_status(CompletedProcess(["git"], 0, raw, b"")))
        self.assertFalse(guard.clean_worktree_status(CompletedProcess(["git"], 1, b"", b"")))
        self.assertFalse(guard.clean_worktree_status(CompletedProcess(["git"], 0, "", b"")))
        self.assertFalse(guard.clean_worktree_status(CompletedProcess(["git"], 0, bytearray(), b"")))

    def test_real_branch_checker_rejects_dirty_checkout(self):
        # Run the real control logic using only synthetic git outputs.
        from unittest.mock import patch
        from subprocess import CompletedProcess
        good = evidence((("A", "tests/test_scope_literal_ownership_20261016.py"),))
        paths = set(guard.OWNED_EXACT) | {"tests/test_scope_literal_ownership_20261016.py"}
        tree = b"".join(
            b"100644 blob " + b"a" * 40 + b"\t" + item.encode() + b"\0"
            for item in sorted(paths)
        )
        def simulated(*args):
            label = args[0]
            out = {
                "merge-base": b"",
                "rev-parse": b"a" * 40 + b"\n",
                "diff": good,
                "ls-tree": tree,
                "status": b" M src/lightup/scope.py\0",
                "symbolic-ref": guard.EXPECTED_BRANCH.encode("ascii") + b"\n",
            }
            return CompletedProcess(args, 0, out[label], b"")
        with patch.object(guard, "_git", side_effect=simulated):
            self.assertEqual(guard.main(), 1)

    def test_workflow_checks_clean_checkout_after_tests(self):
        workflow = (ROOT / ".github" / "workflows" / "scope-literal-controls-20261016.yml").read_text()
        branch_proof = "python scripts/check_scope_literal_branch_20261016.py"
        self.assertEqual(workflow.count(branch_proof), 2)
        self.assertLess(workflow.index(branch_proof), workflow.index("python scripts/check_scope_literal_suite_20261016.py"))
        self.assertGreater(workflow.rindex(branch_proof), workflow.index("test \"$bad_out\""))

    def test_branch_identity_requires_exact_owner_lane(self):
        from subprocess import CompletedProcess
        branch = guard.EXPECTED_BRANCH.encode("ascii") + b"\n"
        head = CompletedProcess(["git"], 0, b"a" * 40 + b"\n", b"")
        def ref(data: bytes, rc: int = 0):
            return CompletedProcess(["git"], rc, data, b"")
        self.assertTrue(guard.branch_identity(ref(branch), head, {}))
        for candidate in (b"main\n", b"other-worker\n", b"chatgpt/scope-control-char-literal-review-20261016-2327x\n", b""):
            self.assertFalse(guard.branch_identity(ref(candidate), head, {}))
        self.assertFalse(guard.branch_identity(ref(b"", 1), head, {}))
        # GitHub's SHA checkout is detached, but its push event has a frozen
        # exact ref and SHA; a PR merge ref is never acceptable.
        ci = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.EXPECTED_BRANCH,
            "GITHUB_SHA": "a" * 40,
        }
        self.assertTrue(guard.branch_identity(ref(b"", 1), head, ci))
        for key, invalid in (
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/pull/123/merge"),
            ("GITHUB_SHA", "b" * 40),
        ):
            with self.subTest(key=key):
                altered = dict(ci, **{key: invalid})
                self.assertFalse(guard.branch_identity(ref(b"", 1), head, altered))

    def test_missing_required_worker_files_is_hold(self):
        for required in guard.OWNED_EXACT:
            with self.subTest(path=required):
                reduced = b"".join(
                    b"A\0" + path.encode("ascii") + b"\0"
                    for path in guard.OWNED_EXACT if path != required
                )
                self.assertFalse(guard.safe_diff(reduced))


if __name__ == "__main__":
    unittest.main()
