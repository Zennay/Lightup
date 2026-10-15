"""Synthetic, zero-I/O concurrency tests for the #1173 reference only."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Event, Thread
import unittest

from lab.scope_stepup_revalidation_reference_20261015 import (
    OfflineRevalidationFence, ReferenceApproval, ReviewRequest, ToolSnapshot,
)


NOW = datetime(2026, 10, 15, 15, 0, tzinfo=timezone.utc)


def fixture():
    request = ReviewRequest(
        "lab-run", "lab-client", "lab-engagement", "lab-asset",
        "lab-tool", "lab-capability", 5,
    )
    approval = ReferenceApproval(request, NOW - timedelta(minutes=1),
                                 NOW + timedelta(minutes=10))
    tool = ToolSnapshot("lab-tool", "lab-capability", 5)
    fence = OfflineRevalidationFence()
    fence.replace_synthetic_reference(approval, tool)
    return fence, request, approval, tool


class SyntheticRevalidationFenceTests(unittest.TestCase):
    def assert_non_authorizing(self, receipt, status):
        rendered = receipt.as_dict()
        self.assertEqual(rendered["status"], status)
        for name in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "dispatch_allowed", "merge_approved", "release_approved",
        ):
            self.assertIs(rendered[name], False)
        self.assertNotIn("lab-", str(rendered))
        self.assertEqual(set(rendered), {
            "status", "reason", "authorization_verified", "permit_issued",
            "execution_enabled", "dispatch_allowed", "merge_approved",
            "release_approved",
        })

    def test_matching_snapshot_is_only_review_never_permission(self):
        fence, request, _, _ = fixture()
        self.assert_non_authorizing(fence.review(request, NOW), "REVIEW_ONLY")
        self.assertEqual(fence.review_count, 1)

    def test_missing_or_revoked_approval_is_atomic_hold(self):
        fence, request, _, _ = fixture()
        fence.revoke()
        self.assert_non_authorizing(fence.review(request, NOW), "HOLD")
        self.assertEqual(fence.review_count, 0)

    def test_expired_and_premature_snapshots_hold(self):
        fence, request, approval, tool = fixture()
        self.assert_non_authorizing(
            fence.review(request, approval.expires_at), "HOLD"
        )
        self.assert_non_authorizing(
            fence.review(request, approval.issued_at - timedelta(microseconds=1)),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_tenant_run_engagement_asset_tool_capability_and_risk_binding(self):
        for field, bad in (
            ("run", "lab-other-run"), ("client", "lab-other-client"),
            ("engagement", "lab-other-engagement"), ("asset", "lab-other-asset"),
            ("tool", "lab-other-tool"), ("capability", "lab-other-capability"),
            ("risk", 4),
        ):
            with self.subTest(field=field):
                fence, request, _, _ = fixture()
                self.assert_non_authorizing(
                    fence.review(replace(request, **{field: bad}), NOW), "HOLD"
                )
                self.assertEqual(fence.review_count, 0)

    def test_current_tool_registry_identity_is_checked(self):
        fence, request, _, _ = fixture()
        fence.replace_synthetic_tool(ToolSnapshot("lab-other", "lab-capability", 5))
        self.assert_non_authorizing(fence.review(request, NOW), "HOLD")

    def test_probe_false_nonboolean_or_exception_denies(self):
        for result in (False, None, 1, "yes", [], {}):
            with self.subTest(result=type(result)):
                fence, request, _, _ = fixture()
                self.assert_non_authorizing(
                    fence.review(request, NOW, isolation_probe=lambda: result),
                    "HOLD",
                )
                self.assertEqual(fence.review_count, 0)
        fence, request, _, _ = fixture()
        def bad_probe():
            raise RuntimeError("private lab-asset detail")
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=bad_probe), "HOLD"
        )

    def test_revoke_during_probe_cannot_pass_stale_epoch(self):
        fence, request, _, _ = fixture()
        def revoke_during_probe():
            fence.revoke()
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=revoke_during_probe),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_tool_swap_during_probe_cannot_pass_stale_epoch(self):
        fence, request, _, _ = fixture()
        def swap_during_probe():
            fence.replace_synthetic_tool(ToolSnapshot("lab-other", "lab-capability", 5))
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=swap_during_probe),
            "HOLD",
        )

    def test_reissue_same_data_during_probe_rejected_by_epoch_aba(self):
        fence, request, approval, tool = fixture()
        def reissue():
            fence.replace_synthetic_reference(approval, tool)
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=reissue), "HOLD"
        )

    def test_revoke_in_separate_thread_before_final_review(self):
        fence, request, _, _ = fixture()
        entered, resume, done = Event(), Event(), Event()
        results = []
        def probe():
            entered.set()
            self.assertTrue(resume.wait(2))
            return True
        def review_worker():
            try:
                results.append(fence.review(request, NOW, isolation_probe=probe))
            finally:
                done.set()
        worker = Thread(target=review_worker, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            fence.revoke()
        finally:
            resume.set()
            worker.join(timeout=2)
        self.assertTrue(done.is_set())
        self.assertEqual(len(results), 1)
        self.assert_non_authorizing(results[0], "HOLD")
        self.assertEqual(fence.review_count, 0)

    def test_registry_change_in_separate_thread_before_final_review(self):
        fence, request, _, _ = fixture()
        entered, resume = Event(), Event()
        results = []
        def probe():
            entered.set()
            self.assertTrue(resume.wait(2))
            return True
        worker = Thread(
            target=lambda: results.append(
                fence.review(request, NOW, isolation_probe=probe)
            ),
            daemon=True,
        )
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            fence.replace_synthetic_tool(
                ToolSnapshot("lab-tool", "lab-other-capability", 5)
            )
        finally:
            resume.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        self.assert_non_authorizing(results[0], "HOLD")

    def test_caller_mutation_does_not_change_owned_snapshots(self):
        fence, request, approval, tool = fixture()
        object.__setattr__(approval, "expires_at", NOW - timedelta(days=7))
        object.__setattr__(tool, "capability", "lab-mutated")
        object.__setattr__(request, "asset", "lab-mutated")
        stable = ReviewRequest("lab-run", "lab-client", "lab-engagement",
                               "lab-asset", "lab-tool", "lab-capability", 5)
        self.assert_non_authorizing(fence.review(stable, NOW), "REVIEW_ONLY")

    def test_corrupt_time_shapes_never_get_approved(self):
        fence, request, approval, tool = fixture()
        for bad in (None, False, 0, "2026-10-15", datetime(2026, 10, 15)):
            with self.subTest(bad=repr(bad)):
                self.assert_non_authorizing(fence.review(request, bad), "HOLD")
                with self.assertRaises(ValueError):
                    fence.replace_synthetic_reference(
                        replace(approval, expires_at=bad), tool
                    )

    def test_fake_labels_and_subclasses_rejected_before_probe(self):
        class PretendStr(str):
            pass
        class PretendRequest(ReviewRequest):
            pass
        fence, request, approval, tool = fixture()
        for fake in (
            replace(request, run="customer-private"),
            replace(request, asset="lab-asset\\n"),
            replace(request, client=PretendStr("lab-client")),
            replace(request, risk=True),
            PretendRequest(**request.__dict__),
        ):
            called = []
            self.assert_non_authorizing(
                fence.review(fake, NOW, isolation_probe=lambda: called.append(1)),
                "HOLD",
            )
            self.assertEqual(called, [])
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(
                replace(approval, request=replace(request, risk=True)), tool
            )

    def test_plain_review_receipt_does_not_escape_target_identifiers(self):
        fence, request, _, _ = fixture()
        result = fence.review(request, NOW, isolation_probe=lambda: True)
        self.assert_non_authorizing(result, "REVIEW_ONLY")
        self.assertEqual(fence.review_count, 1)


if __name__ == "__main__":
    unittest.main()
