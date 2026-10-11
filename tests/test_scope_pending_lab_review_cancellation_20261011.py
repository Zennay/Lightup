"""Durable, scope-bound cancellation of pending-only lab review intake."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from lightup.destructive_lab_review_queue import LabReviewRequest, PendingLabReviewQueue


class DurableCancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "review.sqlite"
        self.queue = PendingLabReviewQueue(self.path)
        self.request = LabReviewRequest("run-a", "tenant-a", "eng-a", "asset-a", "cap", "tool-a")

    def pending(self, tenant="tenant-a", engagement="eng-a", run="run-a"):
        return self.queue.pending_for_run(tenant, engagement, run)

    def test_run_cancel_withdraws_all_tools_and_assets(self):
        self.queue.submit(self.request)
        self.queue.submit(replace(self.request, tool_id="tool-b"))
        self.queue.submit(replace(self.request, asset="asset-b"))
        self.assertTrue(self.queue.withdraw_run("tenant-a", "eng-a", "run-a"))
        self.assertEqual(self.pending(), ())
        self.assertIsNone(self.queue.submit(replace(self.request, tool_id="tool-c")))
        self.assertIsNone(self.queue.submit(replace(self.request, asset="asset-c")))

    def test_run_cancel_is_durable_even_when_no_requests_existed(self):
        self.assertTrue(self.queue.withdraw_run("tenant-a", "eng-a", "run-a"))
        self.assertFalse(self.queue.withdraw_run("tenant-a", "eng-a", "run-a"))
        self.assertIsNone(PendingLabReviewQueue(self.path).submit(self.request))

    def test_run_cancel_does_not_affect_other_tenant_engagement_or_run(self):
        self.queue.withdraw_run("tenant-a", "eng-a", "run-a")
        for other in (replace(self.request, client_id="tenant-b"),
                      replace(self.request, engagement_id="eng-b"),
                      replace(self.request, run_id="run-b")):
            with self.subTest(other=other):
                self.assertIsNotNone(self.queue.submit(other))
        self.assertEqual(self.pending(), ())

    def test_asset_cancel_blocks_all_tools_on_exact_asset_but_not_siblings(self):
        self.queue.submit(self.request)
        self.queue.submit(replace(self.request, tool_id="tool-b"))
        self.queue.submit(replace(self.request, asset="asset-b"))
        self.assertTrue(self.queue.withdraw_asset("tenant-a", "eng-a", "run-a", "asset-a"))
        self.assertEqual([r.request.asset for r in self.pending()], ["asset-b"])
        self.assertIsNone(self.queue.submit(replace(self.request, tool_id="tool-c")))
        self.assertIsNotNone(self.queue.submit(replace(self.request, asset="asset-b", tool_id="tool-c")))

    def test_asset_cancel_persists_and_is_idempotent(self):
        self.assertTrue(self.queue.withdraw_asset("tenant-a", "eng-a", "run-a", "asset-a"))
        self.assertFalse(self.queue.withdraw_asset("tenant-a", "eng-a", "run-a", "asset-a"))
        reopened = PendingLabReviewQueue(self.path)
        self.assertIsNone(reopened.submit(self.request))
        self.assertIsNotNone(reopened.submit(replace(self.request, asset="asset-b")))

    def test_asset_cancel_is_exactly_tenant_engagement_and_run_bound(self):
        self.queue.withdraw_asset("tenant-a", "eng-a", "run-a", "asset-a")
        for other in (replace(self.request, client_id="tenant-b"),
                      replace(self.request, engagement_id="eng-b"),
                      replace(self.request, run_id="run-b"),
                      replace(self.request, asset="asset-b")):
            with self.subTest(other=other):
                self.assertIsNotNone(self.queue.submit(other))

    def test_malformed_cancel_never_mutates_pending_or_creates_tombstone(self):
        self.queue.submit(self.request)
        for invalid in ("", " tenant-a", "tenant-a\n", None, True, 5, "x" * 257):
            with self.subTest(invalid=repr(invalid)):
                self.assertFalse(self.queue.withdraw_run(invalid, "eng-a", "run-a"))
                self.assertFalse(self.queue.withdraw_asset("tenant-a", "eng-a", "run-a", invalid))
        self.assertEqual(len(self.pending()), 1)
        self.assertIsNotNone(self.queue.submit(replace(self.request, tool_id="tool-b")))

    def test_cancellation_vs_parallel_submits_never_leaves_pending(self):
        with ThreadPoolExecutor(max_workers=10) as pool:
            tasks = [pool.submit(self.queue.submit, replace(self.request, tool_id=f"tool-{i}"))
                     for i in range(24)]
            cancellation = pool.submit(self.queue.withdraw_run, "tenant-a", "eng-a", "run-a")
            self.assertTrue(cancellation.result())
            for task in tasks:
                task.result()
        self.assertEqual(self.pending(), ())
        self.assertIsNone(self.queue.submit(replace(self.request, tool_id="new-tool")))

    def test_cancel_asset_vs_parallel_submits_never_leaves_that_asset(self):
        with ThreadPoolExecutor(max_workers=10) as pool:
            tasks = [pool.submit(self.queue.submit, replace(self.request, tool_id=f"tool-{i}"))
                     for i in range(24)]
            cancellation = pool.submit(self.queue.withdraw_asset, "tenant-a", "eng-a", "run-a", "asset-a")
            self.assertTrue(cancellation.result())
            for task in tasks:
                task.result()
        self.assertEqual(self.pending(), ())
        self.assertIsNotNone(self.queue.submit(replace(self.request, asset="asset-b")))


if __name__ == "__main__":
    unittest.main()
