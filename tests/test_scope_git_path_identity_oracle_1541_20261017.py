"""Pure byte-manifest repair oracle acceptance for #1541.

All fixtures synthetic and disconnected. Does not run Git, network, workers,
scans, handlers, grants or release. Original source REDs live in a separate file.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scope_git_path_identity_oracle_1541 import (
    CheckedGitPath, PathIdentityHold, parse_git_path_outputs,
)


class ByteExactGitPathOracleTests(unittest.TestCase):
    def assert_hold(self, status, stat):
        with self.assertRaises(PathIdentityHold) as exc:
            parse_git_path_outputs(status, stat)
        self.assertEqual(str(exc.exception), "HOLD: ambiguous Git path identity")
        for forbidden in ("secret", "token", "café", "admin"):
            self.assertNotIn(forbidden, str(exc.exception))

    def test_plain_ascii_modified_with_exact_counts(self):
        self.assertEqual(
            parse_git_path_outputs(b"M\0a.py\0", b"1\t2\ta.py\0"),
            (CheckedGitPath("M", "a.py", None, 1, 2),),
        )

    def test_unicode_filename_has_stable_identity(self):
        self.assertEqual(
            parse_git_path_outputs(b"M\0caf\xc3\xa9.py\0",
                                   b"2\t1\tcaf\xc3\xa9.py\0"),
            (CheckedGitPath("M", "café.py", None, 2, 1),),
        )

    def test_tab_path_is_unambiguous_with_nul_frames(self):
        self.assertEqual(
            parse_git_path_outputs(b"M\0part\tname.py\0",
                                   b"1\t1\tpart\tname.py\0"),
            (CheckedGitPath("M", "part\tname.py", None, 1, 1),),
        )

    def test_rename_requires_original_and_destination(self):
        self.assertEqual(
            parse_git_path_outputs(
                b"R100\0src/a.py\0lib/b.py\0",
                b"0\t0\t\0src/a.py\0lib/b.py\0",
            ),
            (CheckedGitPath("R", "lib/b.py", "src/a.py", 0, 0),),
        )

    def test_binary_change_is_explicit_none_not_missing_identity(self):
        self.assertEqual(
            parse_git_path_outputs(b"M\0assets/p.bin\0",
                                   b"-\t-\tassets/p.bin\0"),
            (CheckedGitPath("M", "assets/p.bin", None, None, None),),
        )

    def test_two_canonical_distinct_paths(self):
        self.assertEqual(
            len(parse_git_path_outputs(
                b"M\0a.py\0M\0b.py\0",
                b"1\t1\ta.py\0" + b"1\t1\tb.py\0",
            )),
            2,
        )

    def test_invalid_utf8_never_collapses(self):
        self.assert_hold(b"M\0\xfe.py\0M\0\xff.py\0",
                         b"1\t1\t\xfe.py\0" + b"1\t1\t\xff.py\0")

    def test_incompatible_git_quoted_numstat_is_hold(self):
        self.assert_hold(b"M\0caf\xc3\xa9.py\0",
                         b'1\t1\t"caf\\303\\251.py"\0')

    def test_duplicate_path_is_hold(self):
        self.assert_hold(b"M\0secret.py\0M\0secret.py\0",
                         b"1\t1\tsecret.py\0" * 2)

    def test_casefold_path_alias_is_hold(self):
        self.assert_hold(b"M\0Token.py\0M\0token.py\0",
                         b"1\t1\tToken.py\0" + b"1\t1\ttoken.py\0")

    def test_unicode_normalization_alias_is_hold(self):
        self.assert_hold(b"M\0caf\xc3\xa9.py\0M\0cafe\xcc\x81.py\0",
                         b"1\t1\tcaf\xc3\xa9.py\0"
                         + b"1\t1\tcafe\xcc\x81.py\0")

    def test_mismatched_numstat_is_hold(self):
        self.assert_hold(b"M\0a.py\0", b"1\t1\tb.py\0")

    def test_truncated_nul_streams_are_hold(self):
        for status, stat in (
            (b"M\0a.py", b"1\t1\ta.py\0"),
            (b"M\0a.py\0", b"1\t1\ta.py"),
            (b"M\0", b"1\t1\ta.py\0"),
            (b"R100\0from.py\0", b"1\t1\t\0from.py\0to.py\0"),
            (b"M\0a.py\0", b"1\t1\t\0from.py\0"),
        ):
            with self.subTest(status=status, stat=stat):
                self.assert_hold(status, stat)

    def test_authority_sounding_metadata_is_not_a_status(self):
        self.assert_hold(b"AUTHORIZATION_GRANTED\0a.py\0",
                         b"1\t1\ta.py\0")

    def test_numeric_bounds_and_malformed_lines_are_hold(self):
        for bad in (b"1e9999", b"1000000001", b"0002", b"-1",
                    b"NaN", b"3.14", b"9" * 5000):
            with self.subTest(bad=bad[:15]):
                self.assert_hold(b"M\0a.py\0",
                                 bad + b"\t1\ta.py\0")

    def test_unbounded_status_score_is_hold(self):
        self.assert_hold(b"R" + b"9" * 5000 + b"\0a.py\0b.py\0",
                         b"0\t0\t\0a.py\0b.py\0")

    def test_path_traversal_is_hold(self):
        for name in (b"../secret", b"/secret", b"dir//secret",
                     b"dir/./secret", b"dir/../secret", b"file\nname"):
            with self.subTest(name=name):
                self.assert_hold(b"M\0" + name + b"\0",
                                 b"1\t1\t" + name + b"\0")

    def test_oversize_or_unauthenticated_data_is_hold(self):
        for bad in (b"M\0a.py\0" * 100000, "M\0a.py\0",
                    bytearray(b"M\0a.py\0"), b""):
            with self.subTest(kind=type(bad).__name__):
                self.assert_hold(bad, b"1\t1\ta.py\0")

    def test_missing_entries_or_extra_numstats_are_hold(self):
        self.assert_hold(b"M\0a.py\0",
                         b"1\t1\ta.py\0" + b"1\t1\tb.py\0")
        self.assert_hold(b"M\0a.py\0M\0b.py\0", b"1\t1\ta.py\0")


if __name__ == "__main__":
    unittest.main()
