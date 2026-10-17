"""Offline acceptance for partial GitHub compare coverage (#1553)."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import unittest

from lightup.scope_github_file_coverage_1553 import (
    _MAX_INPUT_BYTES, review, review_json,
)

VERSION = "LIGHTUP-FICTIONAL-GITHUB-FILE-COVERAGE-V1"


def packet():
    return {
        "version": VERSION,
        "synthetic_only": True,
        "expected_base_sha": "a" * 40,
        "expected_head_sha": "b" * 40,
        "observed_base_sha": "a" * 40,
        "observed_head_sha": "b" * 40,
        "expected_changed_files": 2,
        "files": [{"filename": "src/app.py"}, {"filename": "infra/main.tf"}],
        "has_next_page": False,
        "truncated": False,
    }


class FileCoverageReviewTest(unittest.TestCase):
    def assert_denied(self, outcome, status):
        self.assertEqual(outcome["status"], status)
        self.assertIs(outcome["not_authorization"], True)
        for key in ("authorize", "grant", "scan", "handler", "dispatch",
                    "merge", "deploy", "release"):
            self.assertIs(outcome[key], False)
        self.assertEqual(len(outcome), 11)
        self.assertNotIn("src/", str(outcome))

    def test_matching_metadata_is_review_only_not_authority(self):
        self.assert_denied(review(packet()), "REVIEW_ONLY")

    def test_order_has_no_effect(self):
        p = packet()
        p["files"].reverse()
        self.assertEqual(review(p), review(packet()))

    def test_missing_last_page_is_hold(self):
        p = packet()
        p["files"].pop()
        self.assert_denied(review(p), "HOLD")

    def test_extra_file_is_hold(self):
        p = packet()
        p["files"].append({"filename": "docs/third.md"})
        self.assert_denied(review(p), "HOLD")

    def test_duplicate_file_is_hold(self):
        p = packet()
        p["files"][1] = p["files"][0]
        self.assert_denied(review(p), "HOLD")

    def test_same_sha_is_hold(self):
        p = packet()
        p["expected_head_sha"] = p["observed_head_sha"] = "a" * 40
        self.assert_denied(review(p), "HOLD")

    def test_head_sha_mismatch_is_hold(self):
        p = packet()
        p["observed_head_sha"] = "c" * 40
        self.assert_denied(review(p), "HOLD")

    def test_base_sha_mismatch_is_hold(self):
        p = packet()
        p["observed_base_sha"] = "d" * 40
        self.assert_denied(review(p), "HOLD")

    def test_noncanonical_sha_is_hold(self):
        for bad in ("A" * 40, "g" * 40, "b" * 39, "b" * 41, True, 1, []):
            with self.subTest(bad=bad):
                p = packet()
                p["expected_head_sha"] = bad
                self.assert_denied(review(p), "HOLD")

    def test_next_page_even_complete_length_is_hold(self):
        p = packet()
        p["has_next_page"] = True
        self.assert_denied(review(p), "HOLD")

    def test_truncated_even_complete_length_is_hold(self):
        p = packet()
        p["truncated"] = True
        self.assert_denied(review(p), "HOLD")

    def test_oversize_expected_count_is_hold(self):
        p = packet()
        p["expected_changed_files"] = 301
        self.assert_denied(review(p), "HOLD")

    def test_zero_expected_count_is_hold(self):
        p = packet()
        p["expected_changed_files"] = 0
        p["files"] = []
        self.assert_denied(review(p), "HOLD")

    def test_bool_and_float_counts_are_hold(self):
        for bad in (True, False, 2.0, -1, "2", None):
            with self.subTest(bad=bad):
                p = packet()
                p["expected_changed_files"] = bad
                self.assert_denied(review(p), "HOLD")

    def test_missing_or_extra_field_is_hold(self):
        for variant in ("missing", "extra"):
            p = packet()
            if variant == "missing":
                del p["truncated"]
            else:
                p["is_authorized"] = True
            self.assert_denied(review(p), "HOLD")

    def test_untrusted_fake_authority_fields_do_not_pass(self):
        p = packet()
        p["grant"] = True
        self.assert_denied(review(p), "HOLD")

    def test_wrong_marker_and_synthetic_mode_are_hold(self):
        for name, bad in (("version", VERSION + "2"), ("version", True),
                          ("synthetic_only", 1), ("synthetic_only", False)):
            p = packet()
            p[name] = bad
            self.assert_denied(review(p), "HOLD")

    def test_exact_bool_pagination_flags_required(self):
        for key in ("truncated", "has_next_page"):
            for bad in (0, 1, None, "false", []):
                with self.subTest(key=key, bad=bad):
                    p = packet()
                    p[key] = bad
                    self.assert_denied(review(p), "HOLD")

    def test_nonbuiltin_file_shapes_are_hold(self):
        for bad in (True, {}, (), "abc", None):
            p = packet()
            p["files"] = bad
            self.assert_denied(review(p), "HOLD")

    def test_file_metadata_extra_or_missing_key_is_hold(self):
        for bad in ({}, {"filename": "src/app.py", "is_safe": True},
                    {"filename": None}, {"filename": []}):
            p = packet()
            p["files"][0] = bad
            self.assert_denied(review(p), "HOLD")

    def test_unsafe_names_do_not_echo(self):
        for bad in ("../secret", "/etc/passwd", "a//b", "a/./b",
                    "a/../b", "a\\b", "bad\x00key", "a\nsecret",
                    "x" * 4097, "", "x/"):
            with self.subTest(name=bad[:12]):
                p = packet()
                p["files"][0]["filename"] = bad
                self.assert_denied(review(p), "HOLD")

    def test_duplicate_json_keys_are_rejected_before_review(self):
        raw = json.dumps(packet()).replace('"truncated": false', '"truncated": false, "truncated": false')
        with self.assertRaises(ValueError):
            review_json(raw.encode())

    def test_nonfinite_json_is_rejected(self):
        raw = json.dumps(packet()).replace('"expected_changed_files": 2', '"expected_changed_files": NaN')
        with self.assertRaises(ValueError):
            review_json(raw.encode())

    def test_oversize_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            review_json(b"x" * (_MAX_INPUT_BYTES + 1))

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            review_json(b"\xff\xfe")

    def run_cli(self, raw: bytes, args=("--synthetic-only",)):
        env = dict(os.environ)
        proc = subprocess.run(
            [sys.executable, "-m", "lightup.scope_github_file_coverage_1553", *args],
            input=raw, capture_output=True, timeout=5, env=env,
        )
        self.assertFalse(proc.stderr, proc.stderr.decode(errors="replace"))
        verdict = json.loads(proc.stdout.decode())
        self.assertNotEqual(proc.returncode, 0)
        return proc.returncode, verdict

    def test_real_subprocess_review_only_is_exit_three(self):
        code, outcome = self.run_cli(json.dumps(packet()).encode())
        self.assertEqual(code, 3)
        self.assert_denied(outcome, "REVIEW_ONLY")

    def test_real_subprocess_partial_list_is_exit_two(self):
        p = packet()
        p["files"].pop()
        code, outcome = self.run_cli(json.dumps(p).encode())
        self.assertEqual(code, 2)
        self.assert_denied(outcome, "HOLD")

    def test_real_subprocess_empty_and_wrong_options_fail_closed(self):
        for args in ((), ("--help",), ("--live",), ("--synthetic-only", "--release")):
            code, outcome = self.run_cli(b"", args)
            self.assertEqual(code, 2)
            self.assert_denied(outcome, "HOLD")

    def test_real_subprocess_malformed_json_does_not_echo(self):
        raw = b'{"filename": "SECRET_SENTINEL", "truncated":'
        code, outcome = self.run_cli(raw)
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_SENTINEL", str(outcome))

    @unittest.expectedFailure
    def test_unrepaired_original_github_adapter_cannot_prove_file_completeness(self):
        # Explicit original-owner RED. Does not edit or patch the source owner.
        from lightup.github_changes import github_pull_request_changeset
        # Caller says there were two files; the source adapter accepts one.
        with self.assertRaises(ValueError):
            github_pull_request_changeset(
                client_id="fictional", repository="example/repo", pr_number=1,
                base_sha="a" * 40, head_sha="b" * 40,
                files=[{"filename": "src/app.py", "status": "added",
                        "additions": 1, "deletions": 0}],
                too_large=False,
            )


if __name__ == "__main__":
    unittest.main()
