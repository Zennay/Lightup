from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_retest_authorization_preflight as preflight_tests
from lightup.ai.orchestration import ToolDefinition
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.future_security_retest_tool_policy_review import (
    RETEST_TOOL_POLICY_CATALOG_REVIEW_SCHEMA_VERSION,
    FutureRetestToolPolicyCatalogStatus,
    build_future_security_retest_tool_policy_catalog_review,
)


class FutureSecurityRetestToolPolicyCatalogReviewTest(unittest.TestCase):
    def setUp(self):
        self.p = preflight_tests.FutureSecurityRetestAuthorizationPreflightTest(
            "test_valid_recurring_grant_is_eligible_only_for_later_policy_review"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state
        self.checked_at = self.p.checked_at

    def _inputs(self, *, suffix="tool-policy"):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self.p._build(suffix=suffix)
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        )

    @staticmethod
    def _valid_tools(request):
        return tuple(
            ToolDefinition(
                tool_id=f"lab-{capability_id}-review",
                capability_id=capability_id,
                interaction=InteractionKind.LAB_ACTIVE,
                min_risk=RiskLevel.LOW_IMPACT,
                description=f"Planning-only catalog fixture for {capability_id}",
            )
            for capability_id in request.requested_capability_ids
        )

    def _review(
        self,
        *,
        suffix="tool-policy",
        tools=None,
        preflight_override=None,
    ):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix=suffix)
        definitions = self._valid_tools(request) if tools is None else tools
        reviewed = build_future_security_retest_tool_policy_catalog_review(
            preflight if preflight_override is None else preflight_override,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            definitions,
        )
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            reviewed,
        )

    def test_lab_candidate_metadata_never_creates_execution_authority(self):
        *_, request, binding, grant, preflight, review = self._review(
            suffix="tool-policy-valid"
        )
        self.assertEqual(
            review.status,
            FutureRetestToolPolicyCatalogStatus.CANDIDATE_METADATA_AVAILABLE,
        )
        self.assertTrue(review.tool_policy_review_complete)
        self.assertFalse(review.tool_selection_allowed)
        self.assertFalse(review.tool_call_created)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)
        self.assertEqual(review.future_semantics, "unresolved")
        self.assertEqual(review.security_verdict, "not_evaluated")
        self.assertEqual(review.request_sha256, request.request_sha256)
        self.assertEqual(review.preflight_sha256, preflight.preflight_sha256)
        self.assertEqual(
            review.authorization_grant_sha256,
            preflight.authorization_grant_sha256,
        )
        self.assertEqual(review.authorization_max_risk, int(grant.scope.max_risk))
        self.assertTrue(
            all(item.candidate_tool_ids for item in review.capability_reviews)
        )
        self.assertTrue(
            all(item.gap_reason is None for item in review.capability_reviews)
        )

    def test_target_active_and_over_risk_tools_are_not_candidates(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix="tool-policy-rejections")
        capability_id = request.requested_capability_ids[0]
        definitions = [
            ToolDefinition(
                tool_id="real-target-probe",
                capability_id=capability_id,
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.LOW_IMPACT,
                description="Must never become a future-state catalog candidate",
            ),
            ToolDefinition(
                tool_id="elevated-lab-probe",
                capability_id=capability_id,
                interaction=InteractionKind.LAB_ACTIVE,
                min_risk=RiskLevel.ELEVATED,
                description="Above the existing authorization ceiling",
            ),
        ]
        for other_capability in request.requested_capability_ids[1:]:
            definitions.append(
                ToolDefinition(
                    tool_id=f"lab-{other_capability}-review",
                    capability_id=other_capability,
                    interaction=InteractionKind.LAB_ACTIVE,
                    min_risk=RiskLevel.LOW_IMPACT,
                    description="Valid metadata fixture",
                )
            )

        review = build_future_security_retest_tool_policy_catalog_review(
            preflight,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            tuple(definitions),
        )
        first = review.capability_reviews[0]
        self.assertEqual(first.candidate_tool_ids, ())
        self.assertEqual(first.gap_reason, "no_eligible_lab_tool_metadata")
        self.assertEqual(
            review.status,
            FutureRetestToolPolicyCatalogStatus.CATALOG_GAP_REQUIRES_REVIEW,
        )
        rejection_map = {
            (item.tool_id, item.reason)
            for item in first.rejections
        }
        self.assertIn(
            ("real-target-probe", "interaction_not_lab_active:target_active"),
            rejection_map,
        )
        self.assertIn(
            ("elevated-lab-probe", "risk_above_authorized_max"),
            rejection_map,
        )
        self.assertFalse(review.tool_selection_allowed)
        self.assertFalse(review.tool_call_created)

    def test_duplicate_tool_ids_and_unknown_capabilities_fail_closed(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix="tool-policy-invalid-catalog")
        capability_id = request.requested_capability_ids[0]

        duplicate = (
            ToolDefinition(
                "duplicate-tool",
                capability_id,
                InteractionKind.LAB_ACTIVE,
                RiskLevel.LOW_IMPACT,
                "first",
            ),
            ToolDefinition(
                "duplicate-tool",
                capability_id,
                InteractionKind.LAB_ACTIVE,
                RiskLevel.LOW_IMPACT,
                "second",
            ),
        )
        with self.assertRaisesRegex(ValueError, "duplicate tool definition"):
            build_future_security_retest_tool_policy_catalog_review(
                preflight,
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                duplicate,
            )

        unknown = (
            *self._valid_tools(request),
            ToolDefinition(
                "unknown-capability-tool",
                "not-a-real-capability",
                InteractionKind.LAB_ACTIVE,
                RiskLevel.LOW_IMPACT,
                "invalid catalog metadata",
            ),
        )
        with self.assertRaisesRegex(ValueError, "references unknown capability"):
            build_future_security_retest_tool_policy_catalog_review(
                preflight,
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                unknown,
            )

    def test_missing_candidate_is_explicit_not_a_pass(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix="tool-policy-gap")

        review = build_future_security_retest_tool_policy_catalog_review(
            preflight,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            (),
        )
        self.assertEqual(
            review.status,
            FutureRetestToolPolicyCatalogStatus.CATALOG_GAP_REQUIRES_REVIEW,
        )
        self.assertTrue(review.capability_reviews)
        self.assertTrue(
            all(
                item.gap_reason == "no_eligible_lab_tool_metadata"
                for item in review.capability_reviews
            )
        )
        self.assertTrue(
            all(not item.candidate_tool_ids for item in review.capability_reviews)
        )
        self.assertFalse(review.tool_selection_allowed)
        self.assertFalse(review.execution_allowed)

    def test_tampered_preflight_is_rejected_by_live_revalidation(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix="tool-policy-tamper")
        tampered = dataclasses.replace(preflight, preflight_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "preflight is stale"):
            build_future_security_retest_tool_policy_catalog_review(
                tampered,
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                self._valid_tools(request),
            )

    def test_review_is_deterministic_catalog_bound_and_json_serializable(self):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self._inputs(suffix="tool-policy-deterministic")
        definitions = self._valid_tools(request)
        before = dataclasses.asdict(current)

        first = build_future_security_retest_tool_policy_catalog_review(
            preflight,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            definitions,
        )
        second = build_future_security_retest_tool_policy_catalog_review(
            preflight,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            tuple(reversed(definitions)),
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first.schema_version,
            RETEST_TOOL_POLICY_CATALOG_REVIEW_SCHEMA_VERSION,
        )
        self.assertEqual(len(first.tool_catalog_sha256), 64)
        self.assertEqual(len(first.review_sha256), 64)
        int(first.tool_catalog_sha256, 16)
        int(first.review_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["review_sha256"], first.review_sha256)
        self.assertEqual(
            exported["tool_catalog_sha256"],
            first.tool_catalog_sha256,
        )
        self.assertEqual(exported["tool_selection_allowed"], False)
        self.assertEqual(exported["tool_call_created"], False)
        self.assertEqual(exported["execution_allowed"], False)


if __name__ == "__main__":
    unittest.main()
