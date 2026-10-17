"""Offline PR-vs-compare consistency, never authentication, for scope #1540."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_pr_compare_pair_offline_1540.py"
spec = importlib.util.spec_from_file_location("scope1540_pair", SCRIPT)
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)
PIN = "d" * 40
REPO = "Zennay/Lightup"


def review(worker, number, head, files, *, branch=None):
    branch = branch or "review/" + worker
    return {"worker": worker, "branch": branch,
            "pr": {"number": number, "state": "open", "draft": True,
                   "base_sha": PIN, "head_sha": head, "head_ref": branch,
                   "changed_files": len(files), "head_repo_full_name": REPO},
            "compare": {"base_sha": PIN, "head_sha": head,
                        "status": "ahead", "ahead_by": 2, "behind_by": 0,
                        "too_large": False, "files": files,
                        "repository_full_name": REPO}}


def file(status, filename, previous_filename=None):
    data = {"status": status, "filename": filename}
    if previous_filename is not None:
        data["previous_filename"] = previous_filename
    return data


GOOD = {"version": 1, "base_sha": PIN, "repository_full_name": REPO, "reviews": [
    review("scope-a", 1537, "a" * 40,
           [file("renamed", "docs/updated.md", "docs/original.md")]),
    review("scope-b", 1539, "b" * 40, [file("added", "tests/new.py")]),
]}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


class PairedSourceConsistencyTests(unittest.TestCase):
    def test_good_pair_only_review(self):
        self.assertEqual(pair.check(encode(GOOD)), "REVIEW_ONLY")

    def test_renamed_source_collision_holds(self):
        import copy
        item = copy.deepcopy(GOOD)
        item["reviews"][1]["compare"]["files"] = [file("modified", "docs/ORIGINAL.md")]
        self.assertEqual(pair.check(encode(item)), "HOLD")

    def test_cross_repository_or_fork_mismatch_holds(self):
        import copy
        cases = (
            ("root", "repository_full_name", "Other/Repository"),
            ("pr", "head_repo_full_name", "Other/Repository"),
            ("compare", "repository_full_name", "Other/Repository"),
            ("root", "repository_full_name", "../Lightup"),
            ("root", "repository_full_name", "Zennay//Lightup"),
            ("pr", "head_repo_full_name", None),
            ("compare", "repository_full_name", True),
        )
        for section, key, bad in cases:
            with self.subTest(section=section, bad=bad):
                item = copy.deepcopy(GOOD)
                dest = item if section == "root" else item["reviews"][0][section]
                dest[key] = bad
                self.assertEqual(pair.check(encode(item)), "HOLD")
        for section, key in (("root", "repository_full_name"),
                             ("pr", "head_repo_full_name"),
                             ("compare", "repository_full_name")):
            item = copy.deepcopy(GOOD)
            dest = item if section == "root" else item["reviews"][0][section]
            del dest[key]
            self.assertEqual(pair.check(encode(item)), "HOLD")

    def test_wrong_head_or_base_either_view_holds(self):
        import copy
        for section, field, value in (
            ("pr", "head_sha", "c" * 40),
            ("compare", "head_sha", "c" * 40),
            ("pr", "base_sha", "c" * 40),
            ("compare", "base_sha", "c" * 40),
            ("pr", "head_sha", "d" * 40),
            ("pr", "head_ref", "review/other"),
        ):
            with self.subTest(section=section, field=field, value=value):
                value_to_check = copy.deepcopy(GOOD)
                value_to_check["reviews"][0][section][field] = value
                self.assertEqual(pair.check(encode(value_to_check)), "HOLD")

    def test_duplicate_pull_request_number_is_hold(self):
        import copy
        value = copy.deepcopy(GOOD)
        value["reviews"][1]["pr"]["number"] = value["reviews"][0]["pr"]["number"]
        self.assertEqual(pair.check(encode(value)), "HOLD")

    def test_duplicate_head_different_pr_is_hold(self):
        import copy
        value = copy.deepcopy(GOOD)
        for section in ("pr", "compare"):
            value["reviews"][1][section]["head_sha"] = value["reviews"][0][section]["head_sha"]
        self.assertEqual(pair.check(encode(value)), "HOLD")

    def test_untrusted_release_or_approval_claims_hold(self):
        import copy
        for name, value in (("approved", True), ("release_allowed", False),
                            ("consent_verified", True)):
            with self.subTest(name=name):
                altered = copy.deepcopy(GOOD)
                altered[name] = value
                self.assertEqual(pair.check(encode(altered)), "HOLD")
                altered = copy.deepcopy(GOOD)
                altered["reviews"][0]["pr"][name] = value
                self.assertEqual(pair.check(encode(altered)), "HOLD")

    def test_not_draft_closed_or_bad_metadata_holds(self):
        import copy
        for field, bad in (("state", "closed"), ("state", "merged"),
                           ("state", "OPEN"), ("draft", False), ("draft", 1),
                           ("number", 0), ("number", True),
                           ("changed_files", 2), ("changed_files", False),
                           ("changed_files", "1")):
            with self.subTest(field=field, bad=bad):
                data = copy.deepcopy(GOOD)
                data["reviews"][0]["pr"][field] = bad
                self.assertEqual(pair.check(encode(data)), "HOLD")

    def test_changed_file_count_compare_details_and_missing_previous_hold(self):
        import copy
        for field, bad in (("behind_by", 1), ("ahead_by", 0),
                           ("too_large", True), ("too_large", None),
                           ("status", "diverged"), ("status", "identical")):
            with self.subTest(field=field, bad=bad):
                data = copy.deepcopy(GOOD)
                data["reviews"][0]["compare"][field] = bad
                self.assertEqual(pair.check(encode(data)), "HOLD")
        data = copy.deepcopy(GOOD)
        del data["reviews"][0]["compare"]["files"][0]["previous_filename"]
        self.assertEqual(pair.check(encode(data)), "HOLD")

    def test_reordered_list_can_be_reviewed_without_grant(self):
        import copy
        data = copy.deepcopy(GOOD)
        data["reviews"].reverse()
        self.assertEqual(pair.check(encode(data)), "REVIEW_ONLY")

    def test_input_encoding_dupkeys_and_truncated_fail(self):
        data = encode(GOOD)
        for input_bytes in (data[:1], data[:-1], b"\xff" + data,
                            data + b"\n", b" " + data,
                            b'{"version":1,"version":1}',
                            b"0" * 65537):
            with self.subTest(head=input_bytes[:20]):
                self.assertEqual(pair.check(input_bytes), "HOLD")

    def test_end_to_end_cli_never_authorizes(self):
        for input_data, expected, exit_code in (
            (encode(GOOD), "REVIEW_ONLY", 3),
            (b'{"secret":"fictional"}', "HOLD", 2),
        ):
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                    input=input_data, capture_output=True, timeout=8)
            self.assertEqual(result.returncode, exit_code, result.stderr)
            self.assertEqual(result.stderr, b"")
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], expected)
            self.assertEqual(len(payload), 7)
            self.assertTrue(all(value is False for key, value in payload.items()
                                if key != "status"))
            self.assertNotIn(b"fictional", result.stdout)

    def test_not_a_network_or_process_client(self):
        with (mock.patch("socket.socket", side_effect=AssertionError("network")),
              mock.patch("subprocess.run", side_effect=AssertionError("process")),
              mock.patch("builtins.open", side_effect=AssertionError("file"))):
            self.assertEqual(pair.check(encode(GOOD)), "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
