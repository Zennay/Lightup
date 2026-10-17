"""Offline acceptance: exhaustive synthetic GitHub-PR pagination (#1553)."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import lightup.scope_github_pr_pages_1553 as sut


def meta(count=2):
    return {
        "version": "LIGHTUP-FICTIONAL-GITHUB-REST-PAGES-V1",
        "synthetic_only": True,
        "repository": "fictional/example",
        "pr_number": 42,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "changed_files": count,
    }


def make_record(n):
    return {
        "filename": f"src/test_{n:03d}.py",
        "status": "added",
        "additions": 1,
        "deletions": 0,
        "patch": "@@ -0,0 +1 @@\n+allow: false\n",
    }


def pages(count):
    records = [make_record(n) for n in range(count)]
    return [
        {"page": i // 100 + 1, "per_page": 100, "files": records[i:i + 100]}
        for i in range(0, count, 100)
    ]


class SyntheticPRPageAcceptance(unittest.TestCase):
    def assert_denied(self, receipt, status="HOLD"):
        self.assertEqual(receipt["status"], status)
        self.assertIs(receipt["not_authorization"], True)
        self.assertEqual(len(receipt), 13)
        for effect in ("authorize", "grant", "scan", "handler", "dispatch",
                       "merge", "deploy", "release"):
            self.assertIs(receipt[effect], False)
        self.assertNotIn("src/", str(receipt))
        self.assertNotIn("allow:", str(receipt))
        if status == "HOLD":
            self.assertEqual(receipt["file_count"], 0)
            self.assertEqual(receipt["inferred_signal_count"], 0)

    def assert_pre_adapter_hold(self, before, file_pages, after):
        with mock.patch.object(sut, "preview",
                               side_effect=AssertionError("must not call adapter")) as spy:
            self.assert_denied(sut.review_pages(before, file_pages, after))
            spy.assert_not_called()

    def test_single_page_consistent_is_still_review_only(self):
        b = meta()
        self.assert_denied(sut.review_pages(b, pages(2), copy.deepcopy(b)), "REVIEW_ONLY")

    def test_exact_page_boundaries_and_full_300_file_ceiling(self):
        for count in (1, 2, 99, 100, 101, 199, 200, 201, 299, 300):
            with self.subTest(count=count):
                b = meta(count)
                r = sut.review_pages(b, pages(count), copy.deepcopy(b))
                self.assert_denied(r, "REVIEW_ONLY")
                self.assertEqual(r["file_count"], count)

    def test_actual_installed_changeset_is_called_once_only_after_all_pages(self):
        b = meta(101)
        with mock.patch.object(sut, "preview", wraps=sut.preview) as spy:
            r = sut.review_pages(b, pages(101), copy.deepcopy(b))
            self.assertEqual(spy.call_count, 1)
            claim, records = spy.call_args.args
            self.assertEqual(claim["expected_changed_files"], 101)
            self.assertEqual(claim["expected_base_sha"], b["base_sha"])
            self.assertEqual(claim["expected_head_sha"], b["head_sha"])
            self.assertFalse(claim["has_next_page"])
            self.assertFalse(claim["truncated"])
            self.assertEqual([e["filename"] for e in claim["files"]],
                             [e["filename"] for e in records])
        self.assert_denied(r, "REVIEW_ONLY")

    def test_one_missing_file_in_last_page_fails_before_adapter(self):
        b = meta(101)
        v = pages(101)
        v[-1]["files"].clear()
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_missing_middle_page_fails(self):
        b = meta(201)
        v = pages(201)
        v.pop(1)
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_duplicate_page_fails(self):
        b = meta(201)
        v = pages(201)
        v[1] = copy.deepcopy(v[0])
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_reordered_pages_fail(self):
        b = meta(101)
        v = pages(101)
        v.reverse()
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_duplicate_file_across_pages_fails(self):
        b = meta(101)
        v = pages(101)
        v[1]["files"][0]["filename"] = v[0]["files"][0]["filename"]
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_claimed_total_too_large_fails(self):
        b = meta(301)
        self.assert_pre_adapter_hold(b, pages(300), copy.deepcopy(b))

    def test_zero_claim_fails(self):
        b = meta(0)
        self.assert_pre_adapter_hold(b, [], copy.deepcopy(b))

    def test_missing_final_page_fails(self):
        b = meta(101)
        self.assert_pre_adapter_hold(b, pages(100), copy.deepcopy(b))

    def test_extra_final_page_fails(self):
        b = meta(100)
        self.assert_pre_adapter_hold(b, pages(101), copy.deepcopy(b))

    def test_short_middle_page_fails(self):
        b = meta(201)
        v = pages(201)
        v[1]["files"].pop()
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_wrong_page_numbers_fail(self):
        for bad in (0, 3, -1, 1.0, True, False, "1", None):
            with self.subTest(bad=bad):
                b = meta(101)
                v = pages(101)
                v[0]["page"] = bad
                self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_wrong_page_size_fails(self):
        for bad in (1, 50, 99, 101, 100.0, True, "100"):
            with self.subTest(bad=bad):
                b = meta()
                v = pages(2)
                v[0]["per_page"] = bad
                self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_page_extra_fields_fail(self):
        b = meta()
        v = pages(2)
        v[0]["extra"] = "yes"
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_page_missing_field_fails(self):
        b = meta()
        v = pages(2)
        del v[0]["files"]
        self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_snapshot_before_after_base_drift_fails(self):
        b = meta()
        a = copy.deepcopy(b)
        a["base_sha"] = "c" * 40
        self.assert_pre_adapter_hold(b, pages(2), a)

    def test_snapshot_before_after_head_drift_fails(self):
        b = meta()
        a = copy.deepcopy(b)
        a["head_sha"] = "c" * 40
        self.assert_pre_adapter_hold(b, pages(2), a)

    def test_snapshot_changed_file_count_drift_fails(self):
        b = meta()
        a = copy.deepcopy(b)
        a["changed_files"] += 1
        self.assert_pre_adapter_hold(b, pages(2), a)

    def test_snapshot_repo_pr_identity_drift_fails(self):
        for key, value in (("repository", "wrong/repo"), ("pr_number", 43),
                           ("synthetic_only", False), ("version", "legacy")):
            with self.subTest(key=key):
                b = meta()
                a = copy.deepcopy(b)
                a[key] = value
                self.assert_pre_adapter_hold(b, pages(2), a)

    def test_unknown_snapshot_keys_fail(self):
        b = meta()
        b["is_authorized"] = True
        self.assert_pre_adapter_hold(b, pages(2), copy.deepcopy(b))

    def test_wrong_snapshot_types_fail(self):
        for key, bad in (("changed_files", 2.0), ("changed_files", True),
                         ("changed_files", None), ("pr_number", True),
                         ("pr_number", 42.0), ("head_sha", "A" * 40),
                         ("base_sha", "g" * 40), ("repository", "../hello"),
                         ("repository", "fake/.."), ("repository", "/fake"),
                         ("repository", "fake\\repo"), ("version", [])):
            with self.subTest(key=key, bad=repr(bad)):
                b = meta()
                b[key] = bad
                self.assert_pre_adapter_hold(b, pages(2), copy.deepcopy(b))

    def test_same_base_and_head_is_hold(self):
        b = meta()
        b["head_sha"] = b["base_sha"]
        self.assert_pre_adapter_hold(b, pages(2), copy.deepcopy(b))

    def test_invalid_filename_and_cross_page_duplicate_hold(self):
        for bad in ("../secret", "/tmp/root", "folder//file", "x\\y", "", "\x00x"):
            with self.subTest(bad=repr(bad)):
                b = meta()
                v = pages(2)
                v[0]["files"][0]["filename"] = bad
                self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_malformed_file_record_cannot_reach_adapter(self):
        b = meta()
        for bad in (None, True, "str", [], 4):
            v = pages(2)
            v[0]["files"][0] = bad
            self.assert_pre_adapter_hold(b, v, copy.deepcopy(b))

    def test_incomplete_or_invalid_patch_flows_to_existing_hold(self):
        b = meta()
        v = pages(2)
        v[0]["files"][0]["patch"] = "@@ -0,0 +1 @@\n"
        self.assert_denied(sut.review_pages(b, v, copy.deepcopy(b)))

    def test_no_mutation_of_caller_packet(self):
        b, v, a = meta(101), pages(101), meta(101)
        original = copy.deepcopy((b, v, a))
        self.assert_denied(sut.review_pages(b, v, a), "REVIEW_ONLY")
        self.assertEqual((b, v, a), original)

    def cli(self, raw, args=("--synthetic-pages-only",)):
        if type(raw) is not bytes:
            raw = json.dumps(raw).encode("utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "lightup.scope_github_pr_pages_1553", *args],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, env=os.environ.copy(),
        )
        self.assertEqual(result.stderr, b"")
        self.assertIn(result.returncode, (2, 3))
        return result.returncode, json.loads(result.stdout)

    def test_cli_valid_packet_only_review_exit3(self):
        b = meta()
        status, output = self.cli({"before": b, "pages": pages(2), "after": b})
        self.assertEqual(status, 3)
        self.assert_denied(output, "REVIEW_ONLY")

    def test_cli_invalid_is_hold_exit2_privacy_minimal(self):
        b = meta()
        v = pages(2)
        v[0]["files"][0]["filename"] = "PRIVATE_CUSTOMER_SENTINEL"
        v[0]["files"][0]["patch"] = "PRIVATE_SECRET_DATA"
        status, output = self.cli({"before": b, "pages": v[:-1], "after": b})
        self.assertEqual(status, 2)
        self.assert_denied(output)
        self.assertNotIn("PRIVATE_SECRET", str(output))
        self.assertNotIn("PRIVATE_CUSTOMER", str(output))

    def test_cli_wrong_mode_never_enables_actions(self):
        for args in ((), ("--live",), ("--synthetic-pages-only", "--authorize")):
            status, output = self.cli(b"{}", args)
            self.assertEqual(status, 2)
            self.assert_denied(output)

    def test_cli_duplicate_json_keys_malformed_utf8_and_nonfinite_hold(self):
        samples = (
            b'{"before":{}, "before":{}, "pages":[], "after":{}}',
            b'\xff', b'{"before":NaN,"pages":[],"after":{}}',
            b'x' * 131073,
        )
        for raw in samples:
            status, output = self.cli(raw)
            self.assertEqual(status, 2)
            self.assert_denied(output)


if __name__ == "__main__":
    unittest.main()
