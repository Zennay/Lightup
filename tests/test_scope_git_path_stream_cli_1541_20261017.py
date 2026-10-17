"""Executable negative/positive acceptance of fictional, non-authorizing #1541 CLI."""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/review_scope_git_path_streams_synthetic_1541.py"
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import review_scope_git_path_streams_synthetic_1541 as reviewer

REQUIRED_FALSE = (
    "authorized", "consent_verified", "permit_issued", "dispatch_allowed",
    "execution_allowed", "merge_allowed", "release_allowed",
)


def document(status=b"M\0src/example.py\0", numstat=b"1\t1\tsrc/example.py\0"):
    return {
        "schema": "lightup.scope_git_paths_synthetic.v1",
        "synthetic_only": True,
        "status_b64": base64.b64encode(status).decode("ascii"),
        "numstat_b64": base64.b64encode(numstat).decode("ascii"),
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class SyntheticGitStreamCliTests(unittest.TestCase):
    def cli(self, raw: bytes, *, expected: int):
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(CLI)],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
        self.assertEqual(completed.returncode, expected)
        self.assertFalse(completed.stderr)
        self.assertEqual(completed.stdout[-1:], b"\n")
        data = json.loads(completed.stdout)
        self.assertEqual(set(REQUIRED_FALSE).difference(data), set())
        self.assertTrue(all(data[field] is False for field in REQUIRED_FALSE))
        self.assertIs(data["synthetic_only"], True)
        self.assertEqual(data["status"], "REVIEW_ONLY" if expected == 3 else "HOLD")
        self.assertEqual(completed.stdout, canonical(data) + b"\n")
        self.assertNotIn(b"src/example.py", completed.stdout)
        return completed.stdout

    def test_one_canonical_fictional_review_returns_never_zero(self):
        self.cli(canonical(document()), expected=3)

    def test_two_ordered_distinct_fictional_records_are_review_only(self):
        st=b"M\0first.py\0M\0second.py\0"
        n=b"1\t1\tfirst.py\0" + b"1\t1\tsecond.py\0"
        self.cli(canonical(document(st, n)), expected=3)

    def test_reordered_streams_are_atomic_hold(self):
        st=b"M\0first.py\0M\0second.py\0"
        n=b"1\t1\tsecond.py\0" + b"1\t1\tfirst.py\0"
        self.cli(canonical(document(st, n)), expected=2)

    def test_invalid_git_paths_are_atomic_hold_without_echo(self):
        for st,n in (
            (b"M\0secret\x80.py\0", b"1\t1\tsecret\x80.py\0"),
            (b"M\0../credential.py\0", b"1\t1\t../credential.py\0"),
            (b"M\0a\0M\0a/b\0", b"1\t1\ta\0" + b"1\t1\ta/b\0"),
            (b"M\0a.py", b"1\t1\ta.py\0"),
        ):
            with self.subTest(case=st[:4]):
                result = self.cli(canonical(document(st,n)), expected=2)
                for token in (b"secret", b"credential", b"a/b"):
                    self.assertNotIn(token, result)

    def test_extra_authority_flag_and_missing_schema_are_hold(self):
        d = document()
        d["authorized"] = True
        self.cli(canonical(d), expected=2)
        d.pop("authorized")
        d.pop("schema")
        self.cli(canonical(d), expected=2)

    def test_no_optin_false_and_forged_review_status_hold(self):
        for invalid in (False, 1, "true", None):
            with self.subTest(value=invalid):
                d = document()
                d["synthetic_only"] = invalid
                self.cli(canonical(d), expected=2)
        d = document()
        d["status"] = "PASS"
        self.cli(canonical(d), expected=2)

    def test_duplicate_keys_and_unsorted_json_are_hold(self):
        valid=canonical(document())
        self.cli(b'{"schema":"x","schema":"y"}', expected=2)
        self.cli(valid.replace(b",", b", ", 1), expected=2)
        self.cli(valid + b"\n", expected=2)

    def test_nonfinite_json_and_invalid_utf8_are_hold(self):
        self.cli(b'{"value":NaN}', expected=2)
        self.cli(b"\xfe\xfd", expected=2)

    def test_rejects_bad_base64_and_noncanonical_padding(self):
        for bad in ("@", "AAAA=", "Q===", "Q", " /w=="):
            with self.subTest(value=bad):
                d=document()
                d["status_b64"]=bad
                self.cli(canonical(d), expected=2)

    def test_empty_and_partial_json_cannot_obtain_review_only(self):
        raw=canonical(document())
        for i in (0, 1, 2, 5, 9, 20, len(raw)//2, len(raw)-1):
            with self.subTest(n=i):
                self.cli(raw[:i], expected=2)

    def test_limit_large_request_is_generic_hold(self):
        self.cli(b" " * 786433, expected=2)

    def test_raw_stream_over_own_limit_is_hold(self):
        d=document(b"M\0a\0"+b"A"*262144)
        self.cli(canonical(d), expected=2)

    def test_source_reviewer_is_pure_without_file_socket_or_command_io(self):
        with patch("builtins.open", side_effect=AssertionError("file-I/O")), \
                patch("subprocess.Popen", side_effect=AssertionError("child-I/O")), \
                patch("pathlib.Path.open", side_effect=AssertionError("path-I/O")), \
                patch("socket.socket", side_effect=AssertionError("network-I/O")):
            self.assertTrue(reviewer._review(canonical(document())))
            self.assertFalse(reviewer._review(canonical(document(b"M\0a\0", b"1\t1\tb\0"))))

    def test_stdout_receipts_never_signal_authority(self):
        for raw in (canonical(document()), canonical(document(b"M\0a\0", b"1\t1\tb\0"))):
            status = 3 if raw == canonical(document()) else 2
            result = self.cli(raw, expected=status)
            self.assertLess(len(result), 300)
            self.assertNotIn(b"true", result.replace(b'"synthetic_only":true', b''))


if __name__ == "__main__":
    unittest.main()
