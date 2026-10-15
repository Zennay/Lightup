"""Synthetic, zero-I/O concurrency tests for the #1173 reference only."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from threading import Event, Thread
import unittest

from lab.scope_stepup_revalidation_reference_20261015 import (
    OfflineRevalidationFence, ReferenceApproval, ReviewReceipt, ReviewRequest,
    ToolSnapshot,
)


NOW = datetime(2026, 10, 15, 15, 0, tzinfo=timezone.utc)


def fixture():
    request = ReviewRequest(
        "lab-run", "lab-client", "lab-engagement", "lab-asset",
        "lab-tool", "lab-capability", 5, NOW,
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
        self.assert_non_authorizing(fence.review(request, NOW, isolation_probe=lambda: True), "REVIEW_ONLY")
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
                               "lab-asset", "lab-tool", "lab-capability", 5, NOW)
        self.assert_non_authorizing(fence.review(stable, NOW, isolation_probe=lambda: True), "REVIEW_ONLY")

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


    def test_registry_aba_swap_back_still_invalidates_precheck(self):
        fence, request, _, tool = fixture()
        def mutate_twice():
            fence.replace_synthetic_tool(ToolSnapshot("lab-other", "lab-capability", 5))
            fence.replace_synthetic_tool(tool)
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=mutate_twice), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_revoke_then_restore_identical_snapshot_still_holds(self):
        fence, request, approval, tool = fixture()
        def restore_after_revoke():
            fence.revoke()
            with self.assertRaises(ValueError):
                fence.replace_synthetic_reference(approval, tool)
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=restore_after_revoke),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_four_waiting_reviewers_all_hold_after_one_revoke(self):
        for _ in range(4):
            fence, request, _, _ = fixture()
            entered = [Event() for i in range(4)]
            release = Event()
            outcomes, errors = [], []
            def worker(i):
                try:
                    def probe():
                        entered[i].set()
                        if not release.wait(3):
                            raise TimeoutError("unreleased synthetic probe")
                        return True
                    outcomes.append(fence.review(request, NOW, isolation_probe=probe))
                except Exception as exc:
                    errors.append(exc)
            threads = [Thread(target=worker, args=(i,), daemon=True) for i in range(4)]
            for thread in threads:
                thread.start()
            try:
                self.assertTrue(all(event.wait(3) for event in entered))
                fence.revoke()
            finally:
                release.set()
                for thread in threads:
                    thread.join(timeout=3)
            self.assertFalse(errors)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(len(outcomes), 4)
            for receipt in outcomes:
                self.assert_non_authorizing(receipt, "HOLD")
            self.assertEqual(fence.review_count, 0)


    def test_frozen_claim_mutated_by_callback_never_retargets_review(self):
        fence, request, _, _ = fixture()
        def corrupt_input():
            object.__setattr__(request, "asset", "lab-other-asset")
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=corrupt_input), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_cannot_mutate_bad_claim_into_good_during_probe(self):
        fence, original, _, _ = fixture()
        request = replace(original, asset="lab-unapproved")
        def launder_input():
            object.__setattr__(request, "asset", original.asset)
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=launder_input), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)


    def test_custom_timezone_callback_is_rejected_without_invocation(self):
        class HostileZone(tzinfo):
            calls = 0
            def utcoffset(self, value):
                self.calls += 1
                raise AssertionError("custom timezone callback executed")
        bad_zone = HostileZone()
        hostile_time = datetime(2026, 10, 15, tzinfo=bad_zone)
        fence, request, approval, tool = fixture()
        self.assert_non_authorizing(fence.review(request, hostile_time), "HOLD")
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(
                replace(approval, issued_at=hostile_time), tool
            )
        self.assertEqual(bad_zone.calls, 0)


    def test_no_isolation_probe_is_never_review_only(self):
        fence, request, _, _ = fixture()
        self.assert_non_authorizing(fence.review(request, NOW), "HOLD")
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=None), "HOLD"
        )
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=True), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_in_place_approval_expiry_widening_without_epoch_is_detected(self):
        fence, request, approval, _ = fixture()
        after_original_expiry = approval.expires_at + timedelta(minutes=1)
        object.__setattr__(
            fence._approval, "expires_at", after_original_expiry + timedelta(days=1)
        )
        self.assert_non_authorizing(
            fence.review(request, after_original_expiry, isolation_probe=lambda: True),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_in_place_registry_replacement_with_same_request_denied(self):
        fence, request, _, _ = fixture()
        object.__setattr__(fence._tool, "capability", "lab-other")
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_in_place_approval_identity_mutation_within_probe_denied(self):
        fence, request, _, _ = fixture()
        def mutate_owned_approval():
            object.__setattr__(
                fence._approval.request, "asset", "lab-other-asset"
            )
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=mutate_owned_approval),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_probe_checked_exactly_once_on_valid_review(self):
        fence, request, _, _ = fixture()
        calls = []
        def probe():
            calls.append(1)
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=probe), "REVIEW_ONLY"
        )
        self.assertEqual(calls, [1])
        self.assertEqual(fence.review_count, 1)
        fence.revoke()
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=probe), "HOLD"
        )
        self.assertEqual(fence.review_count, 1)


    def test_expiry_during_probe_rejects_fresh_clock_observation(self):
        fence, request, approval, _ = fixture()
        self.assert_non_authorizing(
            fence.review(
                request, NOW, isolation_probe=lambda: True,
                fresh_clock_probe=lambda: approval.expires_at,
            ), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_fresh_clock_inside_window_still_only_reviews(self):
        fence, request, approval, _ = fixture()
        calls = []
        def clock():
            calls.append("clock")
            return approval.issued_at + timedelta(minutes=2)
        self.assert_non_authorizing(
            fence.review(
                request, NOW, isolation_probe=lambda: True,
                fresh_clock_probe=clock,
            ), "REVIEW_ONLY"
        )
        self.assertEqual(calls, ["clock"])
        self.assertEqual(fence.review_count, 1)

    def test_fresh_clock_must_be_aware_canonical_and_monotone(self):
        samples = (None, False, 0, "2026-10-15", datetime(2026, 10, 15),
                   NOW - timedelta(microseconds=1))
        for sample in samples:
            with self.subTest(value=type(sample)):
                fence, request, _, _ = fixture()
                self.assert_non_authorizing(
                    fence.review(
                        request, NOW, isolation_probe=lambda: True,
                        fresh_clock_probe=lambda: sample,
                    ), "HOLD"
                )
                self.assertEqual(fence.review_count, 0)

    def test_fresh_clock_callback_revocation_still_invalidates_epoch(self):
        fence, request, _, _ = fixture()
        def current_time():
            fence.revoke()
            return NOW + timedelta(seconds=1)
        self.assert_non_authorizing(
            fence.review(
                request, NOW, isolation_probe=lambda: True,
                fresh_clock_probe=current_time,
            ), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_invalid_clock_callback_is_rejected_before_probe(self):
        fence, request, _, _ = fixture()
        called = []
        for bad in ("yes", 1, True, [], {}):
            self.assert_non_authorizing(
                fence.review(
                    request, NOW,
                    isolation_probe=lambda: called.append(1) or True,
                    fresh_clock_probe=bad,
                ), "HOLD"
            )
        self.assertEqual(called, [])
        def raises():
            raise RuntimeError("lab-secret details")
        self.assert_non_authorizing(
            fence.review(
                request, NOW, isolation_probe=lambda: True,
                fresh_clock_probe=raises,
            ), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)


    def test_poisoned_receipt_status_and_reason_clamp_to_generic_hold(self):
        for status, reason in (
            ("APPROVED", "lab-secret"),
            ("RELEASE", "synthetic_snapshot_consistent"),
            ("REVIEW_ONLY", "lab-secret"),
            ("HOLD", "lab-private"),
            (True, "not_verified"),
            ("APPROVED", None),
        ):
            with self.subTest(status=type(status), reason=type(reason)):
                forged = ReviewReceipt(status, reason)
                receipt = forged.as_dict()
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "not_verified")
                self.assertNotIn("lab-", str(receipt))
                self.assertTrue(all(receipt[name] is False for name in (
                    "authorization_verified", "permit_issued",
                    "execution_enabled", "dispatch_allowed",
                    "merge_approved", "release_approved",
                )))

    def test_tampered_receipt_flags_cannot_claim_review_status(self):
        for name in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "dispatch_allowed", "merge_approved", "release_approved",
        ):
            with self.subTest(name=name):
                forged = ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")
                object.__setattr__(forged, name, True)
                receipt = forged.as_dict()
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "not_verified")
                self.assertIs(receipt[name], False)

    def test_noncanonical_receipt_subclass_never_keeps_review_status(self):
        class ForgedReceipt(ReviewReceipt):
            pass
        forged = ForgedReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")
        result = ReviewReceipt.as_dict(forged)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "not_verified")
        for name in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "dispatch_allowed", "merge_approved", "release_approved",
        ):
            self.assertIs(result[name], False)



    def test_poisoned_hold_receipt_does_not_taint_next_denial(self):
        fence, request, _, _ = fixture()
        first = fence.review(request, NOW)
        self.assert_non_authorizing(first, "HOLD")
        object.__setattr__(first, "status", "REVIEW_ONLY")
        object.__setattr__(first, "reason", "synthetic_snapshot_consistent")
        later = fence.review(request, NOW)
        self.assertIsNot(first, later)
        self.assert_non_authorizing(later, "HOLD")
        self.assertEqual(fence.review_count, 0)

    def test_poisoned_review_receipt_does_not_taint_next_review(self):
        fence, request, _, _ = fixture()
        first = fence.review(request, NOW, isolation_probe=lambda: True)
        self.assert_non_authorizing(first, "REVIEW_ONLY")
        object.__setattr__(first, "status", "APPROVED")
        object.__setattr__(first, "reason", "lab-secret")
        self.assert_non_authorizing(first, "HOLD")
        later = fence.review(request, NOW, isolation_probe=lambda: True)
        self.assertIsNot(first, later)
        self.assert_non_authorizing(later, "REVIEW_ONLY")
        self.assertEqual(fence.review_count, 2)

    def test_deleted_or_incomplete_receipt_fields_fall_to_hold(self):
        for field in ("status", "reason", "permit_issued", "execution_enabled"):
            with self.subTest(field=field):
                victim = ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")
                object.__delattr__(victim, field)
                data = victim.as_dict()
                self.assertEqual(data["status"], "HOLD")
                self.assertEqual(data["reason"], "not_verified")
                self.assertTrue(all(data[name] is False for name in (
                    "authorization_verified", "permit_issued",
                    "execution_enabled", "dispatch_allowed",
                    "merge_approved", "release_approved",
                )))


    def test_pre_run_chronology_rejects_post_run_approval(self):
        fence, request, approval, tool = fixture()
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(
                replace(
                    approval, issued_at=request.started_at,
                    expires_at=request.started_at + timedelta(hours=1),
                ), tool
            )
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(
                replace(
                    approval, issued_at=request.started_at + timedelta(microseconds=1),
                    expires_at=request.started_at + timedelta(hours=1),
                ), tool
            )
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True),
            "REVIEW_ONLY",
        )

    def test_exact_twenty_four_hour_expiry_boundary(self):
        fence, request, approval, tool = fixture()
        within_limit = replace(
            approval, issued_at=NOW - timedelta(hours=23),
            expires_at=NOW + timedelta(hours=1),
        )
        fence.replace_synthetic_reference(within_limit, tool)
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True),
            "REVIEW_ONLY",
        )
        too_long = replace(
            within_limit, expires_at=within_limit.expires_at + timedelta(microseconds=1)
        )
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(too_long, tool)

    def test_noncanonical_run_timestamp_is_rejected(self):
        fence, request, approval, tool = fixture()
        for bad in (None, False, 0, "2026-10-15", datetime(2026, 10, 15)):
            with self.subTest(value=type(bad)):
                bad_request = replace(request, started_at=bad)
                self.assert_non_authorizing(
                    fence.review(
                        bad_request, NOW, isolation_probe=lambda: True
                    ), "HOLD"
                )
                with self.assertRaises(ValueError):
                    fence.replace_synthetic_reference(
                        replace(approval, request=bad_request), tool
                    )

    def test_mutated_run_start_during_probe_denies_review(self):
        fence, request, _, _ = fixture()
        def rewrite_run_start():
            object.__setattr__(
                request, "started_at", NOW + timedelta(microseconds=1)
            )
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=rewrite_run_start),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)


    def test_unexpected_receipt_fields_are_opaque_hold(self):
        victim = ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")
        object.__setattr__(victim, "lab_secret", "lab-sensitive-text")
        receipt = victim.as_dict()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "not_verified")
        self.assertNotIn("lab-", str(receipt))

    def test_deleted_default_backed_dataclass_field_cannot_fall_through(self):
        for name in (
            "authorization_verified", "permit_issued", "execution_enabled",
            "dispatch_allowed", "merge_approved", "release_approved",
        ):
            with self.subTest(field=name):
                result = ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")
                self.assertIn(name, vars(result))
                object.__delattr__(result, name)
                self.assertNotIn(name, vars(result))
                # getattr may fall through to the dataclass class-level False.
                self.assertIs(getattr(result, name), False)
                self.assertEqual(result.as_dict()["status"], "HOLD")


    def test_equivalent_instant_different_timezone_offset_is_detected(self):
        fence, request, _, _ = fixture()
        preserved = fence._approval.expires_at
        shifted = preserved.astimezone(timezone(timedelta(hours=1)))
        self.assertEqual(preserved, shifted)
        self.assertNotEqual(preserved.utcoffset(), shifted.utcoffset())
        object.__setattr__(fence._approval, "expires_at", shifted)
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)

    def test_caller_run_start_equivalent_offset_mutation_denied(self):
        fence, request, _, _ = fixture()
        def shift_timezone_without_changing_instant():
            shifted = request.started_at.astimezone(timezone(timedelta(hours=2)))
            self.assertEqual(shifted, request.started_at)
            object.__setattr__(request, "started_at", shifted)
            return True
        self.assert_non_authorizing(
            fence.review(
                request, NOW, isolation_probe=shift_timezone_without_changing_instant
            ), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_frozen_run_start_fold_bit_mutation_denied(self):
        fence, request, _, _ = fixture()
        original = fence._approval.request.started_at
        folded = original.replace(fold=1)
        self.assertEqual(original, folded)
        object.__setattr__(fence._approval.request, "started_at", folded)
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True),
            "HOLD",
        )
        self.assertEqual(fence.review_count, 0)


    def test_terminal_revoke_cannot_reinstall_previous_approval(self):
        fence, request, approval, tool = fixture()
        fence.revoke()
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(approval, tool)
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True), "HOLD"
        )
        self.assertEqual(fence.review_count, 0)

    def test_terminal_revoke_cannot_reopen_for_different_run(self):
        fence, request, _, tool = fixture()
        fence.revoke()
        different_request = replace(
            request, run="lab-new-run", started_at=NOW + timedelta(minutes=5)
        )
        different_approval = ReferenceApproval(
            different_request, NOW + timedelta(minutes=4),
            NOW + timedelta(minutes=15)
        )
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(different_approval, tool)
        new_fence = OfflineRevalidationFence()
        new_fence.replace_synthetic_reference(different_approval, tool)
        self.assert_non_authorizing(
            new_fence.review(
                different_request, NOW + timedelta(minutes=6),
                isolation_probe=lambda: True
            ), "REVIEW_ONLY"
        )
        self.assert_non_authorizing(fence.review(request, NOW), "HOLD")

    def test_terminal_revoke_never_invokes_probes_or_changes_tool(self):
        fence, request, _, tool = fixture()
        fence.revoke()
        with self.assertRaises(ValueError):
            fence.replace_synthetic_tool(tool)
        events = []
        result = fence.review(
            request, NOW,
            isolation_probe=lambda: events.append("isolation") or True,
            fresh_clock_probe=lambda: events.append("clock") or NOW,
        )
        self.assert_non_authorizing(result, "HOLD")
        self.assertEqual(events, [])
        self.assertEqual(fence.review_count, 0)

    def test_revocation_inside_probe_prevents_reinstall(self):
        fence, request, approval, tool = fixture()
        observed = []
        def poison_probe():
            fence.revoke()
            try:
                fence.replace_synthetic_reference(approval, tool)
            except ValueError:
                observed.append("denied")
            return True
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=poison_probe), "HOLD"
        )
        self.assertEqual(observed, ["denied"])
        self.assertEqual(fence.review_count, 0)

    def test_repeated_terminal_revoke_remains_deny_only(self):
        fence, request, approval, tool = fixture()
        fence.revoke()
        fence.revoke()
        with self.assertRaises(ValueError):
            fence.replace_synthetic_reference(approval, tool)
        self.assert_non_authorizing(
            fence.review(request, NOW, isolation_probe=lambda: True), "HOLD"
        )


if __name__ == "__main__":
    unittest.main()
