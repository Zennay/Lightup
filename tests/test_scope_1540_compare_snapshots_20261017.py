"""Issue #1540: offline GitHub-compare-snapshot admission and no-authority receipts."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/review_scope_compare_snapshots_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_compare", CLI)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
PIN = "d" * 40


def file(status, filename, previous_filename=None):
    result = {"status": status, "filename": filename}
    if previous_filename is not None:
        result["previous_filename"] = previous_filename
    return result


def snap(worker, files, **extras):
    value = {"worker": worker, "branch": "review/" + worker,
             "base_sha": PIN, "head_sha": "a" * 39 + str(len(worker) % 10),
             "compare_status": "ahead", "ahead_by": 2, "behind_by": 0,
             "too_large": False, "expected_file_count": len(files),
             "files": files}
    value.update(extras)
    return value


def document(first=None, second=None):
    return {"version": 1, "base_sha": PIN, "snapshots": [
        first or snap("scope-one", [file("renamed", "src/new.py", "src/old.py")]),
        second or snap("scope-two", [file("added", "docs/b.md")])
    ]}


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


class CompareAdapterTests(unittest.TestCase):
    def test_version1_compare_snapshot_reviews_only_without_conflict(self):
        self.assertEqual(adapter.check(encode(document())), "REVIEW_ONLY")

    def test_old_path_from_rename_conflicts_with_other_worker(self):
        doc = document(second=snap("scope-two", [file("modified", "src/OLD.py")]))
        self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_copy_source_conflicts_with_other_worker(self):
        doc = document(first=snap("scope-one", [
            file("copied", "docs/copy.md", "docs/source.md")]),
            second=snap("scope-two", [file("modified", "DOCS/source.md")]))
        self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_add_modify_remove_operations_normalize_safely(self):
        doc = document(first=snap("scope-one", [
            file("added", "a/new.md"), file("modified", "b/old.md"),
            file("removed", "c/deleted.md")]))
        self.assertEqual(adapter.check(encode(doc)), "REVIEW_ONLY")

    def test_incomplete_misreported_or_truncated_file_list_holds(self):
        for bad in (0, 2, -1, True, "1"):
            with self.subTest(bad=bad):
                doc = document(first=snap("scope-one",
                                         [file("added", "a.md")],
                                         expected_file_count=bad))
                self.assertEqual(adapter.check(encode(doc)), "HOLD")
        doc = document(first=snap("scope-one", [file("added", "a.md")],
                                  too_large=True))
        self.assertEqual(adapter.check(encode(doc)), "HOLD")
        doc["snapshots"][0]["too_large"] = None
        self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_bad_github_compare_status_or_nonzero_behind_holds(self):
        for field, bad in (("compare_status", "diverged"),
                           ("compare_status", "identical"),
                           ("compare_status", "behind"),
                           ("compare_status", "AHEAD"),
                           ("ahead_by", 0), ("ahead_by", True),
                           ("behind_by", 1), ("behind_by", False),
                           ("head_sha", "B" * 40),
                           ("head_sha", ""),
                           ("base_sha", "b" * 40)):
            with self.subTest(field=field, bad=bad):
                doc = document()
                doc["snapshots"][0][field] = bad
                self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_unknown_change_and_missing_rename_identity_hold(self):
        for changed in (
            file("renamed", "dst.py"),
            file("copied", "dst.py"),
            file("unchanged", "dst.py"),
            file("changed", "dst.py"),
            {"status": "added", "filename": "dst.py", "previous_filename": "old.py"},
            {"status": "removed", "filename": "dst.py", "metadata": {}},
            {"status": True, "filename": "dst.py"},
            {"status": "renamed", "filename": "new.py", "previous_filename": None},
        ):
            with self.subTest(changed=changed):
                doc = document(first=snap("scope-one", [changed]))
                self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_unverified_extra_approval_claims_are_rejected(self):
        for location in ("root", "snapshot", "file"):
            doc = document()
            if location == "root":
                doc["authorization"] = True
            elif location == "snapshot":
                doc["snapshots"][0]["verified"] = True
            else:
                doc["snapshots"][0]["files"][0]["allow_merge"] = True
            self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_duplicate_branches_and_worker_alias_holds(self):
        doc = document(second=snap("scope-one", [file("added", "distinct.py")]))
        self.assertEqual(adapter.check(encode(doc)), "HOLD")
        doc = document()
        doc["snapshots"][1]["branch"] = doc["snapshots"][0]["branch"].upper()
        self.assertEqual(adapter.check(encode(doc)), "HOLD")

    def test_broken_json_and_every_prefix_holds(self):
        record = encode(document())
        for size in range(len(record)):
            with self.subTest(size=size):
                self.assertEqual(adapter.check(record[:size]), "HOLD")
        for raw in (record + b"\n", b" " + record, b"{}",
                    b'{"version":1,"version":2}', b"1e9999",
                    b"\xff", b"0" * 65537):
            with self.subTest(raw=raw[:16]):
                self.assertEqual(adapter.check(raw), "HOLD")

    def test_never_calls_remote_compare_or_grant_source(self):
        import socket
        from unittest import mock
        with (mock.patch("socket.socket", side_effect=AssertionError("network")),
              mock.patch("subprocess.run", side_effect=AssertionError("process"))):
            self.assertEqual(adapter.check(encode(document())), "REVIEW_ONLY")

    def test_cli_is_fixed_no_echo_non_authorizing(self):
        for doc, expected, exit_code in (
            (document(), "REVIEW_ONLY", 3),
            (document(second=snap("scope-two", [file("deleted", "secret/path")])),
             "HOLD", 2),
        ):
            done = subprocess.run([sys.executable, "-I", "-S", "-B", str(CLI)],
                                  input=encode(doc), capture_output=True, timeout=10)
            self.assertEqual(done.returncode, exit_code, done.stderr)
            self.assertEqual(done.stderr, b"")
            receipt = json.loads(done.stdout)
            self.assertEqual(receipt["status"], expected)
            self.assertEqual(len(receipt), 7)
            self.assertTrue(all(receipt[key] is False
                                for key in receipt if key != "status"))
            self.assertNotIn(b"secret", done.stdout)


if __name__ == "__main__":
    unittest.main()
