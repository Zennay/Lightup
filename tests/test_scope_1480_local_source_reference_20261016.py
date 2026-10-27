"""#1480 repairability witness: temporary, in-process source wrapper ONLY.

All calls use fictional .example.test metadata. A local unittest.mock.patch
temporarily wraps the installed ActivationGate.issue; this is NEVER installed
in production, imported by an adapter, or permitted as live authorization.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode
from lightup.activation_issuance_window_review_1480 import review_issuance_window
from lightup.models import Authorization, Target
import test_scope_1480_activation_issuance_instant_20261016 as original_acceptance


ORIGINAL_ISSUE = ActivationGate.issue


def _temporary_reference_issue(self, target, capability_id):
    """Temporary repair demonstration, not production code or grant authority.

    The original gate still checks actual scope/policy. Only in this test do
    we discard a synthetic permit whose final stamp fails the pure reviewer.
    """
    permit = ORIGINAL_ISSUE(self, target, capability_id)
    if permit.mode is ActivationMode.AUTHORIZED:
        review = review_issuance_window(
            authorization=target.authorization, issued_at=permit.issued_at
        )
        if review.status != "REVIEW_ONLY":
            raise PermissionError("synthetic permit issuance window HOLD")
    return permit


class IssuanceReference1480Tests(unittest.TestCase):
    def test_unpatched_source_still_produces_expired_synthetic_permit(self):
        with patch("lightup.models.datetime", original_acceptance._InsideCheckClock), patch(
            "lightup.activation.datetime", original_acceptance._OutsideCheckClock
        ):
            permit = original_acceptance._gate().issue(
                original_acceptance._target(), "synthetic-capability"
            )
        self.assertGreater(permit.issued_at, original_acceptance.EXPIRY)
        review = review_issuance_window(
            authorization=original_acceptance._target().authorization,
            issued_at=permit.issued_at,
        )
        self.assertEqual(review.status, "HOLD")
        self.assertFalse(review.may_issue_permits)

    def test_reference_wrapper_turns_original_red_body_into_plain_pass(self):
        case = original_acceptance.ActivationIssuanceInstant1480Tests(
            methodName="test_expected_red_authorized_permit_cannot_be_stamped_after_expiry"
        )
        with patch.object(ActivationGate, "issue", _temporary_reference_issue):
            # Invoke the ORIGINAL expected-RED body without unittest's xfail
            # result conversion; a failing internal assertion propagates.
            case.test_expected_red_authorized_permit_cannot_be_stamped_after_expiry()
        self.assertIs(ActivationGate.issue, ORIGINAL_ISSUE)

    def test_reference_preserves_legitimate_in_window_exact_host(self):
        with patch.object(ActivationGate, "issue", _temporary_reference_issue), patch(
            "lightup.models.datetime", original_acceptance._InsideCheckClock
        ), patch("lightup.activation.datetime", original_acceptance._InsideCheckClock):
            permit = original_acceptance._gate().issue(
                original_acceptance._target(), "synthetic-capability"
            )
        self.assertEqual(permit.issued_at, original_acceptance.INSIDE)
        self.assertEqual(permit.target, original_acceptance.PUBLIC_HOST)
        self.assertIs(ActivationGate.issue, ORIGINAL_ISSUE)

    def test_real_gate_source_retains_permit_after_second_check_grant_shrink(self):
        # ScopePolicy.decide and ActivationGate.issue each check is_current.
        # Shrink the caller-held original window immediately AFTER the second
        # successful check; original permit stamping then sees an expired
        # window. Fictional domain and fully deterministic in-process clocks.
        target = original_acceptance._target()
        original_current = Authorization.is_current
        calls = []

        def shrink_after_second_check(auth, *args, **kwargs):
            allowed = original_current(auth, *args, **kwargs)
            calls.append(allowed)
            if len(calls) == 2 and allowed:
                object.__setattr__(
                    auth, "valid_until",
                    original_acceptance.INSIDE - timedelta(seconds=2),
                )
            return allowed

        with patch.object(Authorization, "is_current", shrink_after_second_check), patch(
            "lightup.models.datetime", original_acceptance._InsideCheckClock
        ), patch("lightup.activation.datetime", original_acceptance._InsideCheckClock):
            permit = original_acceptance._gate().issue(
                target, "synthetic-capability"
            )
        self.assertEqual(calls, [True, True])
        self.assertGreater(permit.issued_at, target.authorization.valid_until)
        verdict = review_issuance_window(
            authorization=target.authorization, issued_at=permit.issued_at,
        )
        self.assertEqual(verdict.status, "HOLD")
        self.assertFalse(verdict.may_issue_permits)

    def test_test_only_wrapper_denies_post_check_grant_shrink(self):
        target = original_acceptance._target()
        original_current = Authorization.is_current
        checks = []

        def shrink_after_second_check(auth, *args, **kwargs):
            allowed = original_current(auth, *args, **kwargs)
            checks.append(allowed)
            if len(checks) == 2 and allowed:
                object.__setattr__(
                    auth, "valid_until",
                    original_acceptance.INSIDE - timedelta(seconds=2),
                )
            return allowed

        with patch.object(ActivationGate, "issue", _temporary_reference_issue), patch.object(
            Authorization, "is_current", shrink_after_second_check
        ), patch("lightup.models.datetime", original_acceptance._InsideCheckClock), patch(
            "lightup.activation.datetime", original_acceptance._InsideCheckClock
        ):
            with self.assertRaises(PermissionError):
                original_acceptance._gate().issue(
                    target, "synthetic-capability"
                )
        self.assertEqual(checks, [True, True])
        self.assertIs(ActivationGate.issue, ORIGINAL_ISSUE)

    def test_reference_preserves_expired_scope_and_plan_only_denials(self):
        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.AUTHORIZED):
            clock = (
                original_acceptance._InsideCheckClock
                if mode is ActivationMode.PLAN_ONLY
                else original_acceptance._OutsideCheckClock
            )
            with self.subTest(mode=mode), patch.object(
                ActivationGate, "issue", _temporary_reference_issue
            ), patch("lightup.models.datetime", clock), patch("lightup.activation.datetime", clock):
                with self.assertRaises(PermissionError):
                    original_acceptance._gate(mode).issue(
                        original_acceptance._target(), "synthetic-capability"
                    )
        self.assertIs(ActivationGate.issue, ORIGINAL_ISSUE)


if __name__ == "__main__":
    unittest.main()
