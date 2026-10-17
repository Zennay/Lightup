"""Offline injected GitHub PR reader acceptance (fictional, no real network)."""
from __future__ import annotations

import copy
import unittest
from unittest import mock

from test_scope_github_pr_pages_1553 import meta, pages
import lightup.scope_github_observer_1553 as sut


class Transport:
    def __init__(self, count=2):
        self.before = meta(count)
        self.after = copy.deepcopy(self.before)
        self.pages = pages(count)
        self.calls = []
        self.fail_at = None

    def fetch_pr(self, repo, number):
        stage = "before" if "pr" not in self.calls else "after"
        self.calls.append("pr")
        if self.fail_at == stage:
            raise OSError("private credential leak sentinel")
        return self.before if stage == "before" else self.after

    def fetch_page(self, repo, number, index, page_size):
        self.calls.append(("page", index, page_size))
        if self.fail_at == index:
            raise TimeoutError("sensitive upstream error")
        if index <= len(self.pages):
            return self.pages[index - 1]
        return {"page": index, "per_page": page_size, "files": []}

    def run(self, **kw):
        return sut.observe(
            self.fetch_pr, self.fetch_page,
            repository="fictional/example", pr_number=42, **kw,
        )


class InjectedTransportTests(unittest.TestCase):
    def assert_hold(self, receipt):
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["file_count"], 0)
        self.assertEqual(receipt["inferred_signal_count"], 0)
        self.assert_deny(receipt)

    def assert_deny(self, receipt):
        self.assertEqual(len(receipt), 13)
        self.assertIs(receipt["not_authorization"], True)
        for key in ("authorize", "grant", "scan", "handler", "dispatch",
                    "merge", "deploy", "release"):
            self.assertIs(receipt[key], False)
        self.assertNotIn("sentinel", str(receipt).lower())
        self.assertNotIn("fictional/example", str(receipt))

    def test_single_page_empty_tail_and_second_snapshot(self):
        client = Transport()
        receipt = client.run()
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["file_count"], 2)
        self.assertEqual(client.calls, ["pr", ("page", 1, 100),
                                        ("page", 2, 100), "pr"])
        self.assert_deny(receipt)

    def test_multi_page_boundaries_and_exact_empty_tail(self):
        for count in (1, 99, 100, 101, 200, 201, 300):
            with self.subTest(count=count):
                client = Transport(count)
                out = client.run()
                self.assertEqual(out["status"], "REVIEW_ONLY")
                self.assertEqual(out["file_count"], count)
                expected_calls = ["pr"] + [
                    ("page", n, 100)
                    for n in range(1, (count + 99) // 100 + 2)
                ] + ["pr"]
                self.assertEqual(client.calls, expected_calls)
                self.assert_deny(out)

    def test_real_inferred_changeset_reached_only_when_complete(self):
        client = Transport(101)
        with mock.patch.object(sut, "review_pages", wraps=sut.review_pages) as spy:
            out = client.run()
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(out["status"], "REVIEW_ONLY")
        before, all_pages, after = spy.call_args.args
        self.assertEqual(before, after)
        self.assertEqual(len(all_pages), 2)
        self.assertEqual([len(p["files"]) for p in all_pages], [100, 1])

    def assert_before_source_hold(self, client):
        with mock.patch.object(sut, "review_pages", wraps=sut.review_pages) as spy:
            out = client.run()
        self.assert_hold(out)
        spy.assert_not_called()

    def test_second_snapshot_head_drift_fails(self):
        c = Transport()
        c.after["head_sha"] = "c" * 40
        self.assert_before_source_hold(c)

    def test_second_snapshot_base_drift_fails(self):
        c = Transport()
        c.after["base_sha"] = "c" * 40
        self.assert_before_source_hold(c)

    def test_changed_files_drift_fails(self):
        c = Transport()
        c.after["changed_files"] = 3
        self.assert_before_source_hold(c)

    def test_repository_or_pr_number_drift_fails(self):
        for key, new_value in (("repository", "other/repository"),
                               ("pr_number", 43)):
            c = Transport()
            c.after[key] = new_value
            self.assert_before_source_hold(c)

    def test_wrong_before_repo_cannot_trigger_page_read(self):
        c = Transport()
        c.before["repository"] = "other/repo"
        c.after = copy.deepcopy(c.before)
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_wrong_before_pr_cannot_trigger_page_read(self):
        c = Transport()
        c.before["pr_number"] = 77
        c.after = copy.deepcopy(c.before)
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_malformed_repo_number_rejected_without_hook_calls(self):
        for repo, num in (("https://github.com/example/repo", 42),
                          ("../../escape", 42), ("bad", 42),
                          ("fictional/example", 0),
                          ("fictional/example", True),
                          ("fictional/example", 42.0),
                          ("fictional/example", 1_000_000_001),
                          ([], 42)):
            c = Transport()
            result = sut.observe(c.fetch_pr, c.fetch_page,
                                 repository=repo, pr_number=num)
            self.assert_hold(result)
            self.assertEqual(c.calls, [])

    def test_invalid_hooks_reject_without_running(self):
        c = Transport()
        self.assert_hold(sut.observe(None, c.fetch_page,
                                     repository="fictional/example", pr_number=42))
        self.assert_hold(sut.observe(c.fetch_pr, True,
                                     repository="fictional/example", pr_number=42))
        self.assertEqual(c.calls, [])

    def test_transient_before_transport_failure_is_hold(self):
        c = Transport()
        c.fail_at = "before"
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_mid_page_transport_failure_is_hold_without_tail(self):
        c = Transport(101)
        c.fail_at = 2
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr", ("page", 1, 100), ("page", 2, 100)])

    def test_trailing_sentinel_transport_failure_is_hold(self):
        c = Transport(101)
        c.fail_at = 3
        self.assert_before_source_hold(c)
        self.assertNotIn("pr", c.calls[1:])

    def test_second_snapshot_transport_failure_is_hold(self):
        c = Transport()
        c.fail_at = "after"
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr", ("page", 1, 100),
                                    ("page", 2, 100), "pr"])

    def test_extra_files_in_empty_tail_are_hold(self):
        c = Transport(100)
        orig = c.fetch_page
        def bad(repo, number, index, size):
            result = orig(repo, number, index, size)
            if index == 2:
                result = copy.deepcopy(result)
                result["files"] = [copy.deepcopy(c.pages[0]["files"][0])]
            return result
        with mock.patch.object(sut, "review_pages", wraps=sut.review_pages) as spy:
            result = sut.observe(c.fetch_pr, bad,
                                 repository="fictional/example", pr_number=42)
        self.assert_hold(result)
        spy.assert_not_called()

    def test_empty_tail_for_exact_300_files_is_mandatory(self):
        c = Transport(300)
        c.fail_at = 4
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls[-1], ("page", 4, 100))

    def test_missing_middle_page_refuses_later_reads(self):
        c = Transport(201)
        c.pages[1]["files"].pop()
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr", ("page", 1, 100), ("page", 2, 100)])

    def test_reversed_page_number_refuses_later_reads(self):
        c = Transport(201)
        c.pages[1]["page"] = 1
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr", ("page", 1, 100), ("page", 2, 100)])

    def test_cross_page_duplicate_refuses_later_reads(self):
        c = Transport(101)
        c.pages[1]["files"][0]["filename"] = c.pages[0]["files"][0]["filename"]
        self.assert_before_source_hold(c)
        self.assertNotIn(("page", 3, 100), c.calls)

    def test_total_above_limit_refuses_file_reads(self):
        c = Transport(300)
        c.before["changed_files"] = 301
        c.after = copy.deepcopy(c.before)
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_false_synthetic_marker_refuses_pages(self):
        c = Transport()
        c.before["synthetic_only"] = False
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_unknown_before_field_refuses_pages(self):
        c = Transport()
        c.before["authorization_granted"] = True
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr"])

    def test_page_response_unknown_field_is_hold(self):
        c = Transport()
        c.pages[0]["request_approved"] = True
        self.assert_before_source_hold(c)

    def test_bad_page_size_or_number_rejected(self):
        for name, value in (("page", True), ("page", 0),
                            ("per_page", "100"), ("per_page", 101)):
            c = Transport()
            c.pages[0][name] = value
            self.assert_before_source_hold(c)

    def test_wrong_page_type_rejected(self):
        c = Transport()
        c.pages[0] = []
        self.assert_before_source_hold(c)

    def test_overlong_patch_exhausts_aggregate_budget(self):
        c = Transport(5)
        c.before["changed_files"] = c.after["changed_files"] = 5
        c.pages = pages(5)
        c.pages[0]["files"][0]["patch"] = "q" * 131072
        self.assert_before_source_hold(c)
        self.assertEqual(c.calls, ["pr", ("page", 1, 100)])

    def test_nonfinite_patch_metadata_is_hold(self):
        c = Transport()
        c.pages[0]["files"][0]["additional"] = float("nan")
        self.assert_before_source_hold(c)

    def test_object_not_serializable_refuses_source(self):
        c = Transport()
        c.pages[0]["files"][0]["patch"] = object()
        self.assert_before_source_hold(c)

    def test_snapshot_alias_mutation_cannot_change_parsed_before(self):
        c = Transport()
        # Deliberately alias both transport snapshots. The first read must be
        # detached before a page callback mutates this shared foreign object.
        c.after = c.before
        orig = c.fetch_page
        def mutate(repo, number, index, size):
            c.before["changed_files"] = 777
            return orig(repo, number, index, size)
        with mock.patch.object(sut, "review_pages", wraps=sut.review_pages) as spy:
            out = sut.observe(c.fetch_pr, mutate,
                              repository="fictional/example", pr_number=42)
        self.assert_hold(out)
        spy.assert_not_called()

    def test_result_never_discloses_transport_exception_data(self):
        c = Transport()
        c.fail_at = "after"
        self.assert_hold(c.run())


if __name__ == "__main__":
    unittest.main()
