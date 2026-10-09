"""Offline tests for the read-only scope PR ownership preflight (no network)."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_scope_pr_overlap import (  # noqa: E402
    GitHubReadOnly, IncompleteEvidence, inspect, normalize_path, overlaps,
    validate_repo,
)


def pr(number, title="scope worker"):
    return {"number": number, "title": title, "head": {"sha": f"{number:040x}"}}


def entry(name, previous=None):
    result = {"filename": name}
    if previous is not None:
        result["previous_filename"] = previous
    return result


class StubGitHub:
    def __init__(self, records=None, error_path=None):
        self.records = records or {}
        self.error_path = error_path
        self.requested = []
        self.headers = []
        self.list_snapshots = 0

    def __call__(self, request, timeout=20):
        parsed = urlsplit(request.full_url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "api.github.com"
        assert request.get_method() == "GET"
        self.headers.append(dict(request.header_items()))
        self.requested.append(request.full_url)
        path = parsed.path.removeprefix("/repos/Zennay/Lightup")
        if path == self.error_path:
            raise HTTPError(request.full_url, 403, "forbidden", {}, None)
        page = int(parse_qs(parsed.query)["page"][0])
        values = self.records.get(path, [])
        if path == "/pulls" and page == 1:
            self.list_snapshots += 1
        if callable(values):
            values = values(self.list_snapshots)
        return io.BytesIO(json.dumps(values[(page - 1) * 100:page * 100]).encode())


class PathValidationTests(unittest.TestCase):
    def test_valid_exact_file_and_directory(self):
        self.assertEqual(normalize_path("tests/a.py"), "tests/a.py")
        self.assertEqual(normalize_path("src/lightup/"), "src/lightup/")
        self.assertEqual(validate_repo("Zennay/Lightup"), "Zennay/Lightup")

    def test_reject_ambiguous_paths_and_repo(self):
        for value in ("", "/etc/passwd", "a//b", "a/../b", "a/./b",
                      "a\\b", "a?", "a#", "a\x00b"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    normalize_path(value)
        for value in ("", "user/repo/evil", "a/..", "a/x?y"):
            with self.subTest(repo=value):
                with self.assertRaises(ValueError):
                    validate_repo(value)

    def test_directory_prefix_has_component_boundary(self):
        self.assertTrue(overlaps("src/lightup/", "src/lightup/execution_policy.py"))
        self.assertFalse(overlaps("src/lightup/", "src/lightup-other/a.py"))
        self.assertFalse(overlaps("src/lightup", "src/lightup/a.py"))
        self.assertTrue(overlaps("src/lightup", "src/lightup"))


class ReadOnlyPreflightTests(unittest.TestCase):
    def client(self, records, **kw):
        stub = StubGitHub(records, error_path=kw.pop("error_path", None))
        return GitHubReadOnly("Zennay/Lightup", "TEST_TOKEN", opener=stub,
                              **kw), stub

    def test_overlap_exact_rename_and_directory_are_reported(self):
        client, stub = self.client({
            "/pulls": [pr(101), pr(102, "other")],
            "/pulls/101/files": [entry("src/lightup/activation.py"),
                                 entry("docs/new.md", previous="docs/old.md")],
            "/pulls/102/files": [entry("tests/safe.py")],
        })
        result = inspect(client, ["src/lightup/", "docs/old.md"], ignore=set())
        self.assertEqual(result["status"], "overlap")
        self.assertEqual(result["inspected_open_prs"], 2)
        self.assertEqual(
            {(x["pr"], x["candidate"]) for x in result["collisions"]},
            {(101, "src/lightup/"), (101, "docs/old.md")},
        )
        self.assertTrue(all("Bearer TEST_TOKEN" in str(h.values()) for h in stub.headers))
        self.assertTrue(all("TEST_TOKEN" not in url for url in stub.requested))

    def test_clear_with_no_overlap_and_explicit_own_ignore(self):
        client, stub = self.client({
            "/pulls": [pr(12), pr(13)],
            "/pulls/12/files": [entry("tests/another_worker.py")],
            "/pulls/13/files": [entry("src/lightup/activation.py")],
        })
        result = inspect(client, ["tests/my_new_test.py"], ignore={13})
        self.assertEqual(result["status"], "clear")
        self.assertEqual(result["inspected_open_prs"], 1)
        self.assertEqual(result["ignored_prs"], [13])
        self.assertFalse(any("/pulls/13/files" in url for url in stub.requested))

    def test_full_first_page_fetches_second_page(self):
        client, stub = self.client({
            "/pulls": [pr(i) for i in range(1, 102)],
        }, max_pages=3)
        result = inspect(client, ["new/path.py"], ignore=set())
        self.assertEqual(result["status"], "clear")
        self.assertEqual(result["inspected_open_prs"], 101)
        self.assertTrue(any("/pulls?per_page=100&page=2" in x for x in stub.requested))

    def test_truncated_pr_list_is_unknown_not_clear(self):
        client, _ = self.client({
            "/pulls": [pr(i) for i in range(1, 101)],
        }, max_pages=1)
        with self.assertRaisesRegex(IncompleteEvidence, "pagination"):
            inspect(client, ["new/path.py"], ignore=set())

    def test_truncated_changed_files_is_unknown_not_clear(self):
        client, _ = self.client({
            "/pulls": [pr(1)],
            "/pulls/1/files": [entry(f"docs/test-{i}.md") for i in range(100)],
        }, max_pages=1)
        with self.assertRaisesRegex(IncompleteEvidence, "pagination"):
            inspect(client, ["src/lightup/activation.py"], ignore=set())

    def test_http_error_is_unknown_and_does_not_echo_token(self):
        client, _ = self.client({"/pulls": [pr(12)]}, error_path="/pulls/12/files")
        with self.assertRaises(IncompleteEvidence) as caught:
            inspect(client, ["test.py"], ignore=set())
        self.assertNotIn("TEST_TOKEN", str(caught.exception))
        self.assertIn("403", str(caught.exception))

    def test_reject_moving_open_pr_set(self):
        client, _ = self.client({
            "/pulls": lambda read: [pr(1)] if read == 1 else [pr(2)],
            "/pulls/1/files": [],
        })
        with self.assertRaisesRegex(IncompleteEvidence, "changed"):
            inspect(client, ["test.py"], ignore=set())

    def test_reject_moving_pr_head_sha(self):
        client, _ = self.client({
            "/pulls": lambda read: [pr(1)] if read == 1
                      else [{**pr(1), "head": {"sha": "f" * 40}}],
            "/pulls/1/files": [],
        })
        with self.assertRaisesRegex(IncompleteEvidence, "changed"):
            inspect(client, ["test.py"], ignore=set())

    def test_reject_duplicate_pr_record(self):
        client, _ = self.client({"/pulls": [pr(1), pr(1)]})
        with self.assertRaisesRegex(IncompleteEvidence, "repeated"):
            inspect(client, ["test.py"], ignore=set())

    def test_malformed_prs_and_file_records_deny(self):
        client, _ = self.client({"/pulls": [{"number": "17"}]})
        with self.assertRaises(IncompleteEvidence):
            inspect(client, ["test.py"], ignore=set())
        client, _ = self.client({
            "/pulls": [pr(17)],
            "/pulls/17/files": [entry("../malformed")],
        })
        with self.assertRaises(IncompleteEvidence):
            inspect(client, ["test.py"], ignore=set())

    def test_open_pr_cap_and_invalid_candidates_deny(self):
        client, _ = self.client({"/pulls": [pr(1), pr(2)]})
        with self.assertRaises(IncompleteEvidence):
            inspect(client, ["new.py"], ignore=set(), max_open_prs=1)
        with self.assertRaises(ValueError):
            inspect(client, ["../not-repo"], ignore=set())


if __name__ == "__main__":
    unittest.main()
