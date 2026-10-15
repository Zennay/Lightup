"""No-network synthetic regression for #773 risk-only non-authorizing review."""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from enum import IntEnum

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from review_scope_direct_risk_claim_773 import (
    ReviewStatus,
    RiskReviewReceipt,
    inspect_direct_scope_risk,
)


class ForeignRisk(IntEnum):
    PASSIVE = 1
    ELEVATED = 4
    SPOOFED = 99


class MisleadingRisk:
    def __int__(self):
        raise AssertionError("foreign risk value was evaluated")

    def __repr__(self):
        raise AssertionError("untrusted details were logged")


class ExplodingScope(ScopeDefinition):
    def __getattribute__(self, item):
        raise AssertionError("foreign scope descriptor was accessed")


class DirectRiskReviewTests(unittest.TestCase):
    def scope(self, risk=RiskLevel.STANDARD):
        return ScopeDefinition(
            assets=("fictional.invalid",),
            max_risk=risk,
            allowed_capabilities=("fictional-capability",),
            excluded_assets=(),
        )

    def assert_non_authorizing(self, receipt):
        self.assertIs(type(receipt.status), ReviewStatus)
        self.assertIn(receipt.status, (ReviewStatus.HOLD, ReviewStatus.REVIEW_ONLY))
        for key in (
            "authorized", "may_scan", "may_dispatch",
            "may_issue_grant", "release_ready", "may_deploy",
        ):
            self.assertIs(getattr(receipt, key), False)

    def test_canonical_levels_never_grant_authority(self):
        levels = (
            RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
            RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED,
        )
        for ceiling in levels:
            for requested in levels:
                with self.subTest(ceiling=ceiling, requested=requested):
                    receipt = inspect_direct_scope_risk(self.scope(ceiling), requested)
                    expected = (ReviewStatus.REVIEW_ONLY if requested.value <= ceiling.value
                                else ReviewStatus.HOLD)
                    self.assertIs(receipt.status, expected)
                    self.assert_non_authorizing(receipt)

    def test_noncanonical_ceiling_types_all_hold(self):
        foreign = (
            -1, 0, 1, 3, 4, 99, True, False, 3.0, 4.0,
            "3", None, ForeignRisk.ELEVATED, ForeignRisk.SPOOFED,
            MisleadingRisk(),
        )
        for max_risk in foreign:
            with self.subTest(case=type(max_risk).__name__):
                receipt = inspect_direct_scope_risk(
                    self.scope(max_risk), RiskLevel.STANDARD
                )
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "noncanonical_risk")
                self.assert_non_authorizing(receipt)

    def test_noncanonical_requested_types_all_hold(self):
        foreign = (
            -1, 0, 1, 3, 4, 99, True, False, 3.0, 4.0,
            "3", None, ForeignRisk.ELEVATED, MisleadingRisk(),
        )
        for request in foreign:
            receipt = inspect_direct_scope_risk(self.scope(), request)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assert_non_authorizing(receipt)

    def test_destructive_lab_tier_always_holds(self):
        for max_risk, requested in (
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.ANALYSIS_ONLY),
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.ELEVATED),
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.DESTRUCTIVE_LAB_ONLY),
            (RiskLevel.ELEVATED, RiskLevel.DESTRUCTIVE_LAB_ONLY),
        ):
            receipt = inspect_direct_scope_risk(self.scope(max_risk), requested)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assertEqual(receipt.reason_code, "lab_only_risk")
            self.assert_non_authorizing(receipt)

    def test_scope_subclasses_and_other_objects_hold_without_access(self):
        foreign = (
            ExplodingScope(("fictional.invalid",), RiskLevel.STANDARD),
            {"max_risk": RiskLevel.STANDARD},
            None,
        )
        for scope in foreign:
            receipt = inspect_direct_scope_risk(scope, RiskLevel.STANDARD)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assert_non_authorizing(receipt)

    def test_output_is_constant_size_and_contains_no_input(self):
        secret = "fictional-sensitive-opaque-marker-773"
        malicious = ScopeDefinition(
            assets=(secret,),
            max_risk=99,
            allowed_capabilities=(secret,),
        )
        receipt = inspect_direct_scope_risk(malicious, RiskLevel.STANDARD)
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn("fictional.invalid", repr(receipt))
        self.assert_non_authorizing(receipt)
        with self.assertRaises(AttributeError):
            receipt.authorized = True

    def test_receipt_constructor_cannot_set_release_flags(self):
        with self.assertRaises(TypeError):
            RiskReviewReceipt(
                ReviewStatus.REVIEW_ONLY, "risk_shape_only", authorized=True
            )
        valid = inspect_direct_scope_risk(
            self.scope(RiskLevel.ELEVATED), RiskLevel.PASSIVE
        )
        denied = inspect_direct_scope_risk(self.scope(99), RiskLevel.PASSIVE)
        for receipt in (valid, denied):
            serialized = receipt.to_dict()
            self.assertEqual(
                set(serialized), {
                    "status", "reason_code", "authorized", "may_scan",
                    "may_dispatch", "may_issue_grant", "release_ready",
                    "may_deploy",
                }
            )
            for key in (
                "authorized", "may_scan", "may_dispatch",
                "may_issue_grant", "release_ready", "may_deploy",
            ):
                self.assertIs(serialized[key], False)
            with self.assertRaises(AttributeError):
                receipt.authorized = True
            with self.assertRaises(AttributeError):
                object.__setattr__(receipt, "may_scan", True)
            serialized["may_scan"] = True
            self.assertIs(receipt.may_scan, False)
            self.assertIs(receipt.to_dict()["may_scan"], False)

    def test_review_receipt_is_exact_immutable_tuple(self):
        receipt = inspect_direct_scope_risk(
            self.scope(RiskLevel.STANDARD), RiskLevel.LOW_IMPACT
        )
        self.assertIs(type(receipt), RiskReviewReceipt)
        self.assertIs(receipt.status, ReviewStatus.REVIEW_ONLY)
        self.assertEqual(len(receipt), 2)
        self.assertEqual(receipt._fields, ("status", "reason_code"))

    def test_canonical_risk_request_order_only_narrows(self):
        levels = [RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
                  RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED]
        for ceiling in levels:
            reviews = [
                inspect_direct_scope_risk(self.scope(ceiling), requested).status
                for requested in levels
            ]
            first_hold = next((idx for idx, s in enumerate(reviews)
                               if s is ReviewStatus.HOLD), len(reviews))
            self.assertTrue(all(s is ReviewStatus.REVIEW_ONLY
                                for s in reviews[:first_hold]))
            self.assertTrue(all(s is ReviewStatus.HOLD
                                for s in reviews[first_hold:]))

    @unittest.expectedFailure
    def test_known_installed_policy_direct_int_99_authority_gap_expected_red(self):
        """Source-owner #773 must eventually reject this, not this reviewer.

        Expected RED documents the installed code gap on main without asserting
        a false passing authorization fix. Remove decorator only after a real
        owner fix makes the negative test pass on the exact tested source head.
        """
        grant = AuthorizationGrant(
            grant_id="synthetic-grant", client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="synthetic-operator", reference="fictional-ref",
            scope=self.scope(99),
            valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        decision = ExecutionPolicy().decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="fictional.invalid",
            capability_id="fictional-capability",
            requested_risk=RiskLevel.STANDARD,
            authorization=grant,
        ))
        self.assertFalse(
            decision.allowed,
            "direct noncanonical scope.max_risk=99 must never authorize TARGET_ACTIVE",
        )


if __name__ == "__main__":
    unittest.main()
