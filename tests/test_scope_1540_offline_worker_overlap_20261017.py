"""Offline-only regression tests for issue #1540; no real GitHub or asset I/O."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_worker_overlap_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_offline", SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

PIN = "a" * 40


def proposal(worker, branch, *paths, base_sha=PIN):
    return {"worker": worker, "branch": branch, "base_sha": base_sha,
            "paths": list(paths)}


def document(*items, pin=PIN):
    return {"version": 1, "base_sha": pin, "proposals": list(items)}


def encode(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


GOOD = document(proposal("scope-a", "chatgpt/isolated-a", "docs/a.md"),
                proposal("scope-b", "chatgpt/isolated-b", "tests/b.py"))


class OfflineWorkerOverlapTests(unittest.TestCase):
    def test_distinct_workers_only_review(self):
        self.assertEqual(review.check(encode(GOOD)), "REVIEW_ONLY")

    def test_exact_collision_and_casefold_alias_hold(self):
        for second in ("src/tool.py", "src/TOOL.py", "SRC/tool.py"):
            with self.subTest(second=second):
                doc = document(proposal("scope-a", "a", "src/tool.py"),
                               proposal("scope-b", "b", second))
                self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_prefix_file_directory_overlap_both_orders(self):
        for first, second in (("src/lightup", "src/lightup/scope.py"),
                              ("src/lightup/scope.py", "src/lightup"),
                              ("A/file", "a/file/deeper")):
            with self.subTest(first=first, second=second):
                doc = document(proposal("scope-a", "a", first),
                               proposal("scope-b", "b", second))
                self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_common_directory_is_not_automatically_conflict(self):
        doc = document(proposal("scope-a", "a", "src/a.py"),
                       proposal("scope-b", "b", "src/b.py"))
        self.assertEqual(review.check(encode(doc)), "REVIEW_ONLY")

    def test_base_sha_must_match_every_proposal(self):
        for altered in ("b" * 40, "", "A" * 40, None):
            with self.subTest(altered=altered):
                doc = document(proposal("scope-a", "a", "a"),
                               proposal("scope-b", "b", "b", base_sha=altered))
                self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_repeated_worker_and_branch_hold(self):
        for items in (
            (proposal("scope-a", "a", "a"), proposal("scope-a", "b", "b")),
            (proposal("scope-a", "a", "a"), proposal("scope-b", "A", "b")),
        ):
            with self.subTest(items=items):
                self.assertEqual(review.check(encode(document(*items))), "HOLD")

    def test_same_proposal_duplicate_alias_hold(self):
        doc = document(proposal("scope-a", "a", "a", "A"),
                       proposal("scope-b", "b", "b"))
        self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_bad_or_ambiguous_paths_hold(self):
        for path in ("../x", "src/../x", "src/./x", "/abs",
                     "a//b", "a\\b", "a/", ".", "..", "x.",
                     "a space", "a\x00b", "schrödinger.py",
                     "a/" + "x" * 101, "a/" * 16 + "z"):
            with self.subTest(path=path):
                doc = document(proposal("scope-a", "a", path),
                               proposal("scope-b", "b", "valid"))
                self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_bad_branch_and_worker_hold(self):
        for branch in ("../x", "/abs", "src//test", "ab..cd", "x.",
                       "-bad", "schrödinger", "a\\b"):
            with self.subTest(branch=branch):
                doc = document(proposal("scope-a", branch, "a"),
                               proposal("scope-b", "b", "b"))
                self.assertEqual(review.check(encode(doc)), "HOLD")
        for worker in ("A", "", "x", "../x", "scope.a", "scope a"):
            with self.subTest(worker=worker):
                doc = document(proposal(worker, "a", "a"),
                               proposal("scope-b", "b", "b"))
                self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_extra_authority_keys_and_bad_shapes_hold(self):
        import copy
        for changed in (
            {"authorized": True},
            {"release_allowed": True},
            {"consent_verified": True},
            {"override": False},
        ):
            doc = copy.deepcopy(GOOD)
            doc.update(changed)
            self.assertEqual(review.check(encode(doc)), "HOLD")
        for key, val in (("version", True), ("version", "1"),
                         ("proposals", {}), ("base_sha", "A" * 40),
                         ("proposals", []), ("proposals", [{}])):
            doc = copy.deepcopy(GOOD)
            doc[key] = val
            self.assertEqual(review.check(encode(doc)), "HOLD")
        doc = copy.deepcopy(GOOD)
        doc["proposals"][0]["authorized"] = False
        self.assertEqual(review.check(encode(doc)), "HOLD")

    def test_duplicate_keys_and_noncanonical_bytes_hold(self):
        canonical = encode(GOOD)
        for raw in (
            b'{"version":1,"version":1,"base_sha":"x","proposals":[]}',
            canonical + b"\n",
            b" " + canonical,
            json.dumps(GOOD).encode(),
            canonical.replace(b'"version":1', b'"version":1.0'),
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'',
            b'\xef\xbb\xbf' + canonical,
            b'\xff' + canonical,
            b'[' * 3000 + b']' * 3000,
            b'0' * (review.MAX_INPUT + 1),
        ):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(review.check(raw), "HOLD")

    def test_exact_path_bytes_differ_across_workers(self):
        altered = document(proposal("scope-a", "a", "src/X.py"),
                           proposal("scope-b", "b", "src/x.py"))
        self.assertEqual(review.check(encode(altered)), "HOLD")

    def test_no_file_network_subprocess_reads_during_check(self):
        with mock.patch("builtins.open", side_effect=AssertionError("file I/O")), \\
             mock.patch("subprocess.run", side_effect=AssertionError("process")), \\
             mock.patch("socket.socket", side_effect=AssertionError("network")):
            self.assertEqual(review.check(encode(GOOD)), "REVIEW_ONLY")

    def test_cli_receipt_only_false_authority_fields(self):
        for raw, status, code in (
            (encode(GOOD), "REVIEW_ONLY", 3),
            (encode(document(proposal("scope-a", "a", "a"),
                             proposal("scope-b", "b", "a"))), "HOLD", 2),
            (b'{"bad":"do not echo me"}', "HOLD", 2),
        ):
            with self.subTest(status=status, raw=raw[:30]):
                result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                        input=raw, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=8, check=False)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], status)
                self.assertEqual(set(receipt), {"status", *review.FLAGS})
                self.assertTrue(all(receipt[k] is False for k in review.FLAGS))
                self.assertNotIn(b"src/", result.stdout)
                self.assertNotIn(b"do not echo", result.stdout)

    def test_no_authorizing_success_exit_exists(self):
        self.assertEqual({review.check(encode(GOOD)),
                          review.check(b"not-json")}, {"REVIEW_ONLY", "HOLD"})


if __name__ == "__main__":
    unittest.main()
