"""Real installed GitHub-ingestion bridge acceptance for fictional scope #1553."""
from __future__ import annotations

import copy
import json
import os
import random
import subprocess
import sys
import unittest
from unittest import mock

import lightup.scope_github_coverage_adapter_1553 as bridge


def packet():
    return {
        "version": "LIGHTUP-FICTIONAL-GITHUB-FILE-COVERAGE-V1",
        "synthetic_only": True,
        "expected_base_sha": "a" * 40,
        "expected_head_sha": "b" * 40,
        "observed_base_sha": "a" * 40,
        "observed_head_sha": "b" * 40,
        "expected_changed_files": 2,
        "files": [{"filename": ".github/workflows/ci.yml"},
                  {"filename": "infra/policy.tf"}],
        "has_next_page": False,
        "truncated": False,
    }


def records():
    return [
        {"filename": ".github/workflows/ci.yml", "status": "added",
         "additions": 1, "deletions": 0, "patch": "@@ -0,0 +1 @@\n+permissions: write-all\n"},
        {"filename": "infra/policy.tf", "status": "modified",
         "additions": 1, "deletions": 1,
         "patch": "@@ -1 +1 @@\n-ingress { cidr_blocks = [\"127.0.0.1/32\"] }\n+ingress { cidr_blocks = [\"0.0.0.0/0\"] }\n"},
    ]


class InstalledBridgeTest(unittest.TestCase):
    def assert_fence(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertIs(result["not_authorization"], True)
        self.assertEqual(len(result), 13)
        for key in ("authorize", "grant", "scan", "handler", "dispatch",
                    "merge", "deploy", "release"):
            self.assertIs(result[key], False)
        if status == "HOLD":
            self.assertEqual(result["file_count"], 0)
            self.assertEqual(result["inferred_signal_count"], 0)
        self.assertNotIn("0.0.0.0", str(result))
        self.assertNotIn("infra/", str(result))

    def test_valid_synthetic_views_reach_real_installed_adapter(self):
        with mock.patch.object(
            bridge, "github_pull_request_changeset",
            wraps=bridge.github_pull_request_changeset,
        ) as spy:
            result = bridge.preview(packet(), records())
            self.assertEqual(spy.call_count, 1)
            args = spy.call_args.kwargs
            self.assertEqual(args["base_sha"], "a" * 40)
            self.assertEqual(args["head_sha"], "b" * 40)
            self.assertFalse(args["too_large"])
            self.assertEqual(len(args["files"]), 2)
        self.assert_fence(result, "REVIEW_ONLY")
        self.assertEqual(result["file_count"], 2)
        self.assertGreaterEqual(result["inferred_signal_count"], 1)

    def test_reordered_files_work_without_promotion(self):
        p = packet()
        r = records()[::-1]
        self.assert_fence(bridge.preview(p, r), "REVIEW_ONLY")

    def test_real_adapter_failure_becomes_hold(self):
        with mock.patch.object(bridge, "github_pull_request_changeset",
                               side_effect=ValueError("private secret sentinel")):
            self.assert_fence(bridge.preview(packet(), records()), "HOLD")

    def assert_rejected_before_adapter(self, p, r):
        with mock.patch.object(bridge, "github_pull_request_changeset",
                               side_effect=AssertionError("adapter must not be called")) as spy:
            self.assert_fence(bridge.preview(p, r), "HOLD")
            spy.assert_not_called()

    def test_missing_record_is_rejected_before_installed_adapter(self):
        self.assert_rejected_before_adapter(packet(), records()[:1])

    def test_overcomplete_record_is_rejected_before_installed_adapter(self):
        r = records()
        r.append({"filename": "docs/extra.md", "status": "added",
                  "additions": 1, "deletions": 0})
        self.assert_rejected_before_adapter(packet(), r)

    def test_wrong_record_filename_is_rejected(self):
        r = records()
        r[0]["filename"] = "outside/hide.py"
        self.assert_rejected_before_adapter(packet(), r)

    def test_duplicate_record_cannot_count_as_complete(self):
        r = records()
        r[1]["filename"] = r[0]["filename"]
        self.assert_rejected_before_adapter(packet(), r)

    def test_revision_mismatch_fails_before_adapter(self):
        p = packet()
        p["observed_head_sha"] = "c" * 40
        self.assert_rejected_before_adapter(p, records())

    def test_next_page_fails_before_adapter(self):
        p = packet()
        p["has_next_page"] = True
        self.assert_rejected_before_adapter(p, records())

    def test_truncated_fails_before_adapter(self):
        p = packet()
        p["truncated"] = True
        self.assert_rejected_before_adapter(p, records())

    def test_unknown_record_fields_fail_before_adapter(self):
        r = records()
        r[0]["promote"] = True
        self.assert_rejected_before_adapter(packet(), r)

    def test_missing_required_metadata_fails_before_adapter(self):
        r = records()
        del r[0]["status"]
        self.assert_rejected_before_adapter(packet(), r)

    def test_status_not_canonical_fails_before_adapter(self):
        for bad in ("deleted", "MODIFIED", "modifiedgarbage", "", [], 1, True):
            with self.subTest(bad=bad):
                r = records()
                r[0]["status"] = bad
                self.assert_rejected_before_adapter(packet(), r)

    def test_stat_counts_fail_closed_on_nonexact_numbers(self):
        for bad in (True, False, 3.1, -1, 1000001, "10", [], None):
            with self.subTest(bad=bad):
                r = records()
                r[0]["additions"] = bad
                self.assert_rejected_before_adapter(packet(), r)

    def test_patch_oversized_and_invalid_types_fail_closed(self):
        for bad in ("x" * 32769, b"raw", True, [], "\ud800"):
            with self.subTest(kind=type(bad).__name__):
                r = records()
                r[0]["patch"] = bad
                self.assert_rejected_before_adapter(packet(), r)

    def test_rename_requires_old_valid_distinct_path(self):
        r = records()
        r[0]["status"] = "renamed"
        self.assert_rejected_before_adapter(packet(), r)
        for bad in ("../a", "", "/tmp/a", ".github/workflows/ci.yml"):
            r = records()
            r[0]["status"] = "renamed"
            r[0]["previous_filename"] = bad
            self.assert_rejected_before_adapter(packet(), r)
        r = records()
        r[0]["status"] = "renamed"
        r[0]["previous_filename"] = ".github/workflows/old.yml"
        self.assert_fence(bridge.preview(packet(), r), "REVIEW_ONLY")

    def test_stray_previous_path_rejected(self):
        r = records()
        r[0]["previous_filename"] = ".github/workflows/old.yml"
        self.assert_rejected_before_adapter(packet(), r)

    def test_missing_patch_is_hold_before_adapter(self):
        r = records()
        del r[0]["patch"]
        self.assert_rejected_before_adapter(packet(), r)

    def test_empty_and_non_diff_patch_are_hold(self):
        for bad in ("", "plain line", "+permissions: write-all", "@@ not a valid hunk\n+x\n"):
            with self.subTest(patch=bad[:15]):
                r = records()
                r[0]["patch"] = bad
                self.assert_rejected_before_adapter(packet(), r)

    def test_mismatched_added_and_deleted_line_stats_are_hold(self):
        r = records()
        r[0]["additions"] += 1
        self.assert_rejected_before_adapter(packet(), r)
        r = records()
        r[1]["deletions"] = 0
        self.assert_rejected_before_adapter(packet(), r)

    def test_truncated_patch_body_is_hold(self):
        r = records()
        r[1]["patch"] = "@@ -1 +1 @@\n+ingress {}\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_unrecognized_diff_line_or_crlf_is_hold(self):
        for bad in (
            "@@ -1 +1 @@\n+safe\nunexpected\n",
            "@@ -1 +1 @@\r\n+safe\r\n",
            "@@@ -1,1 -1,1 +1,1 @@@\n+safe\n",
        ):
            with self.subTest(patch=bad[:25]):
                r = records()
                r[0]["patch"] = bad
                self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_declared_old_span_must_match_body(self):
        r = records()
        r[1]["patch"] = (
            "@@ -1,3 +1,3 @@\n"
            "-ingress { cidr_blocks = [\"127.0.0.1/32\"] }\n"
            "+ingress { cidr_blocks = [\"0.0.0.0/0\"] }\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_declared_new_span_must_match_body(self):
        r = records()
        r[1]["patch"] = (
            "@@ -1 +1,3 @@\n"
            "-ingress { cidr_blocks = [\"127.0.0.1/32\"] }\n"
            "+ingress { cidr_blocks = [\"0.0.0.0/0\"] }\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_overflow_is_hold(self):
        r = records()
        r[0]["patch"] = "@@ -0,0 +1,0 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_zero_ranges_with_visible_lines_are_hold(self):
        r = records()
        r[0]["patch"] = "@@ -0,0 +1,0 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_incomplete_first_hunk_before_second_is_hold(self):
        r = records()
        r[0]["additions"] = 2
        r[0]["patch"] = (
            "@@ -1 +1,2 @@\n+permissions: write-all\n"
            "@@ -10,0 +11 @@\n+allow: all\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_leading_zeros_are_hold(self):
        r = records()
        r[0]["patch"] = "@@ -00,0 +01 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_oversize_declared_ranges_are_hold(self):
        r = records()
        r[0]["patch"] = "@@ -0,0 +1,999999999 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_zero_changes_diff_is_hold(self):
        r = records()
        r[0]["patch"] = "@@ -1 +1 @@\n context only\n"
        r[0]["additions"] = 0
        self.assert_rejected_before_adapter(packet(), r)

    def test_multihunk_diff_counts_match_real_installed_adapter(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["patch"] = (
            "@@ -1 +1,2 @@\n+permissions: write-all\n context\n"
            "@@ -10,0 +11 @@\n+allow: all\n"
        )
        self.assert_fence(bridge.preview(packet(), r), "REVIEW_ONLY")

    def test_duplicate_hunk_coordinates_reject_before_source_adapter(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["patch"] = (
            "@@ -1 +1 @@\n-old\n+new\n"
            "@@ -1 +1 @@\n-old\n+new\n"
        )
        r[0]["deletions"] = 2
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_old_coordinates_out_of_order_reject(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["deletions"] = 2
        r[0]["patch"] = (
            "@@ -15 +15 @@\n-old\n+new\n"
            "@@ -5 +5 @@\n-old\n+new\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_hunk_new_coordinates_out_of_order_reject(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["deletions"] = 2
        r[0]["patch"] = (
            "@@ -5 +15 @@\n-old\n+new\n"
            "@@ -15 +5 @@\n-old\n+new\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_mismatched_unchanged_gaps_are_hold(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["deletions"] = 2
        r[0]["patch"] = (
            "@@ -1 +1 @@\n-old\n+new\n"
            "@@ -11 +80 @@\n-old\n+new\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_first_nonzero_hunk_span_cannot_start_at_zero(self):
        r = records()
        r[0]["patch"] = "@@ -0,1 +1 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_added_status_cannot_remove_existing_lines(self):
        r = records()
        r[0]["patch"] = "@@ -1 +1 @@\n-old\n+new\n"
        r[0]["deletions"] = 1
        self.assert_rejected_before_adapter(packet(), r)

    def test_removed_status_cannot_add_new_lines(self):
        r = records()
        r[0]["status"] = "removed"
        r[0]["patch"] = "@@ -1 +1 @@\n-old\n+new\n"
        r[0]["deletions"] = 1
        self.assert_rejected_before_adapter(packet(), r)

    def test_added_status_requires_zero_old_side_and_zero_deletions(self):
        r = records()
        r[0]["status"] = "added"
        r[0]["patch"] = "@@ -10,0 +11 @@\n+permissions: write-all\n"
        self.assert_rejected_before_adapter(packet(), r)

    def test_removed_status_requires_zero_new_side_and_zero_additions(self):
        r = records()
        r[0]["status"] = "removed"
        r[0]["additions"] = 0
        r[0]["deletions"] = 1
        r[0]["patch"] = "@@ -1 +2,0 @@\n-old\n"
        # A single removal is only coherent at the start of the deleted file.
        self.assert_rejected_before_adapter(packet(), r)

    def test_zero_range_multi_hunk_reuse_reject(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["patch"] = (
            "@@ -0,0 +1 @@\n+first\n"
            "@@ -0,0 +3 @@\n+second\n"
        )
        self.assert_rejected_before_adapter(packet(), r)

    def test_legitimate_sparse_hunks_are_still_review_only(self):
        r = records()
        r[0]["status"] = "modified"
        r[0]["additions"] = 2
        r[0]["deletions"] = 1
        r[0]["patch"] = (
            "@@ -1 +1,2 @@\n-old\n+new\n+more\n"
            "@@ -10 +11 @@\n unchanged\n"
        )
        self.assert_fence(bridge.preview(packet(), r), "REVIEW_ONLY")

    def test_caller_input_purity(self):
        p, r = packet(), records()
        before = copy.deepcopy((p, r))
        self.assert_fence(bridge.preview(p, r), "REVIEW_ONLY")
        self.assertEqual((p, r), before)

    def test_exact_source_model_receives_immutable_snapshot(self):
        p, r = packet(), records()
        before = copy.deepcopy(r)
        with mock.patch.object(
            bridge, "github_pull_request_changeset",
            wraps=bridge.github_pull_request_changeset,
        ) as spy:
            bridge.preview(p, r)
        self.assertEqual(r, before)
        self.assertIsInstance(spy.call_args.kwargs["files"], tuple)
        self.assertIsNot(spy.call_args.kwargs["files"][0], r[0])

    def run_cli(self, envelope, args=("--synthetic-only",)):
        raw = envelope if type(envelope) is bytes else json.dumps(envelope).encode()
        process = subprocess.run(
            [sys.executable, "-m", "lightup.scope_github_coverage_adapter_1553", *args],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, env=os.environ.copy(),
        )
        self.assertEqual(process.stderr, b"")
        self.assertIn(process.returncode, (2, 3))
        return process.returncode, json.loads(process.stdout.decode())

    def test_cli_valid_envelope_is_review_only_never_zero(self):
        code, value = self.run_cli({"coverage": packet(), "records": records()})
        self.assertEqual(code, 3)
        self.assert_fence(value, "REVIEW_ONLY")

    def test_cli_incomplete_is_hold_with_no_raw_patch_leak(self):
        r = records()[:1]
        r[0]["patch"] = "SUPER_SECRET_SENTINEL"
        code, value = self.run_cli({"coverage": packet(), "records": r})
        self.assertEqual(code, 2)
        self.assert_fence(value, "HOLD")
        self.assertNotIn("SUPER_SECRET_SENTINEL", str(value))

    def test_cli_wrong_options_are_hold(self):
        for bad in ((), ("--release",), ("--synthetic-only", "--live")):
            code, value = self.run_cli(b"{}", args=bad)
            self.assertEqual(code, 2)
            self.assert_fence(value, "HOLD")

    def test_cli_double_json_fields_are_hold(self):
        raw = b'{"coverage":{}, "coverage":{}, "records":[]}'
        code, value = self.run_cli(raw)
        self.assertEqual(code, 2)
        self.assert_fence(value, "HOLD")

    def test_cli_nested_duplicate_json_fields_are_hold(self):
        raw = json.dumps({"coverage": packet(), "records": records()})
        raw = raw.replace('"status": "added"', '"status": "added", "status": "added"')
        code, value = self.run_cli(raw.encode())
        self.assertEqual(code, 2)
        self.assert_fence(value, "HOLD")

    def test_cli_oversize_and_nonfinite_are_hold(self):
        for raw in (b"x" * 131073,
                    b'{"coverage": NaN, "records":[]}',
                    b"\xff"):
            code, value = self.run_cli(raw)
            self.assertEqual(code, 2)
            self.assert_fence(value, "HOLD")

    def test_random_mutations_cannot_call_real_adapter(self):
        rng = random.Random(1553)
        for _ in range(110):
            p, r = packet(), records()
            choice = rng.randrange(8)
            if choice == 0: p["expected_changed_files"] = rng.choice([0, 1, 3, 301])
            if choice == 1: p["observed_base_sha"] = "f" * 40
            if choice == 2: p["truncated"] = True
            if choice == 3: p["has_next_page"] = True
            if choice == 4: r[0]["filename"] = "../escape"
            if choice == 5: r[1]["filename"] = r[0]["filename"]
            if choice == 6: r[0]["status"] = "unknown"
            if choice == 7: r[0]["additions"] = -3
            self.assert_rejected_before_adapter(p, r)


if __name__ == "__main__":
    unittest.main()
