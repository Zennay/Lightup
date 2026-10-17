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
