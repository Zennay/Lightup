"""Fail-closed synthetic Git stream parity regressions for LightUp #1541.

All inputs are fictional, already-collected -z byte streams. No subprocess,
filesystem, network, source authorization or tool handler is imported.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scope_git_path_identity_oracle_1541 import (
    PathIdentityHold, parse_git_path_outputs,
)


def stream(*names: str) -> tuple[bytes, bytes]:
    return (
        b"".join(b"M\0" + item.encode("utf-8") + b"\0" for item in names),
        b"".join(b"1\t1\t" + item.encode("utf-8") + b"\0" for item in names),
    )


class GitOutputStreamCoherenceTests(unittest.TestCase):
    def assert_hold(self, status: bytes, numstat: bytes):
        with self.assertRaises(PathIdentityHold) as error:
            parse_git_path_outputs(status, numstat)
        self.assertEqual(str(error.exception), "HOLD: ambiguous Git path identity")
        for secret in ("sensitive", "hidden", "credential"):
            self.assertNotIn(secret, str(error.exception))

    def test_matching_two_file_order_is_reviewable(self):
        st, num = stream("docs/one.md", "src/two.py")
        result = parse_git_path_outputs(st, num)
        self.assertEqual([r.path for r in result], ["docs/one.md", "src/two.py"])

    def test_reordered_numstat_output_must_hold_atomically(self):
        st, _ = stream("src/first.py", "tests/second.py")
        _, different_order = stream("tests/second.py", "src/first.py")
        self.assert_hold(st, different_order)

    def test_reordered_status_output_must_hold_atomically(self):
        _, num = stream("src/first.py", "tests/second.py")
        changed_status, _ = stream("tests/second.py", "src/first.py")
        self.assert_hold(changed_status, num)

    def test_reordered_mixed_rename_and_modified_rows_hold(self):
        st = b"R100\0old.py\0new.py\0M\0later.py\0"
        n = b"1\t1\tlater.py\0" + b"0\t0\t\0old.py\0new.py\0"
        self.assert_hold(st, n)

    def test_ordered_mixed_rename_and_modified_rows_review(self):
        st = b"R100\0old.py\0new.py\0M\0later.py\0"
        n = b"0\t0\t\0old.py\0new.py\0" + b"1\t1\tlater.py\0"
        rows = parse_git_path_outputs(st, n)
        self.assertEqual([(r.status, r.path) for r in rows],
                         [("R", "new.py"), ("M", "later.py")])

    def test_c1_control_characters_hold(self):
        for cp in (0x80, 0x85, 0x9F):
            with self.subTest(cp=cp):
                st, n = stream("docs/name" + chr(cp) + "hidden.py")
                self.assert_hold(st, n)

    def test_tab_and_plain_unicode_still_reviewable(self):
        st, n = stream("src/name\tpart.py", "docs/caf\u00e9.md")
        result = parse_git_path_outputs(st, n)
        self.assertEqual(len(result), 2)

    def test_trailing_dot_or_space_name_holds_across_platforms(self):
        for value in ("src/key. ", "src/key.", "docs/folder./sub.py",
                      "docs/folder /sub.py", "README "):
            with self.subTest(name=repr(value)):
                st, n = stream(value)
                self.assert_hold(st, n)

    def test_ordinary_dots_and_spaces_in_filename_are_reviewable(self):
        st, n = stream("docs/my file.name", "src/pkg/module.py")
        self.assertEqual(len(parse_git_path_outputs(st, n)), 2)

    def test_one_valid_after_one_denied_has_no_session_state(self):
        st, n = stream("src/okay.py", "docs/a\u0085hidden.md")
        self.assert_hold(st, n)
        canonical, stats = stream("src/okay.py")
        self.assertEqual(parse_git_path_outputs(canonical, stats)[0].path,
                         "src/okay.py")

    def test_128_distinct_manifest_records_are_bounded_and_accepted(self):
        names = ["src/file%03d.py" % i for i in range(128)]
        st, n = stream(*names)
        self.assertEqual(len(parse_git_path_outputs(st, n)), 128)

    def test_129_manifest_records_hold_before_partial_result(self):
        names = ["src/file%03d.py" % i for i in range(129)]
        st, n = stream(*names)
        self.assert_hold(st, n)


if __name__ == "__main__":
    unittest.main()
