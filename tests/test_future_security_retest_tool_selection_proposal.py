from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_retest_tool_policy_review as review_tests
from lightup.future_security_retest_tool_selection_proposal import (
    RETEST_TOOL_SELECTION_PROPOSAL_SCHEMA_VERSION,
    FutureSecurityRetestToolSelectionProposalItem,
    build_future_security_retest_tool_selection_proposal,
)


class FutureSecurityRetestToolSelectionProposalTest(unittest.TestCase):
    def setUp(self):
        self.r = review_tests.FutureSecurityRetestToolPolicyCatalogReviewTest(
            "test_lab_candidate_metadata_never_creates_execution_authority"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state
        self.checked_at = self.r.checked_at

    def _inputs(self, *, suffix="tool-selection"):
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
        ) = self.r._review(suffix=suffix)
        definitions = self.r._valid_tools(request)
        selections = tuple(
            FutureSecurityRetestToolSelectionProposalItem(
                capability_id=capability_id,
                proposed_tool_id=f"lab-{capability_id}-review",
            )
            for capability_id in request.requested_capability_ids
        )
        return (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
            definitions,
            selections,
        )

    def _build(self, *, suffix="tool-selection", selections_override=None, review_override=None):
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
            definitions,
            selections,
        ) = self._inputs(suffix=suffix)
        proposal = build_future_security_retest_tool_selection_proposal(
            review if review_override is None else review_override,
            preflight,
            request,
            plan,
            report,
            preview,
            transition,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            definitions,
            selections if selections_override is None else selections_override,
        )
        return (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
            definitions,
            selections,
            proposal,
        )

    def test_valid_explicit_proposal_remains_non_executable(self):
        *_, request, binding, grant, preflight, review, definitions, selections, proposal = (
            self._build(suffix="tool-selection-valid")
        )
        self.assertEqual(
            proposal.schema_version,
            RETEST_TOOL_SELECTION_PROPOSAL_SCHEMA_VERSION,
        )
        self.assertTrue(proposal.proposal_complete)
        self.assertFalse(proposal.selection_authorized)
        self.assertFalse(proposal.tool_call_created)
        self.assertFalse(proposal.arguments_resolved)
        self.assertFalse(proposal.execution_allowed)
        self.assertFalse(proposal.target_interaction_allowed)
        self.assertFalse(proposal.deployment_authorized)
        self.assertFalse(proposal.attack_path_mutation_allowed)
        self.assertEqual(proposal.future_semantics, "unresolved")
        self.assertEqual(proposal.security_verdict, "not_evaluated")
        self.assertEqual(proposal.review_sha256, review.review_sha256)
        self.assertEqual(proposal.tool_catalog_sha256, review.tool_catalog_sha256)
        self.assertEqual(
            {item.capability_id for item in proposal.selections},
            set(request.requested_capability_ids),
        )

    def test_missing_and_duplicate_capability_proposals_fail_closed(self):
        *base, definitions, selections = self._inputs(
            suffix="tool-selection-coverage"
        )
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
        ) = base

        with self.assertRaisesRegex(ValueError, "exactly one explicit proposal"):
            build_future_security_retest_tool_selection_proposal(
                review,
                preflight,
                request,
                plan,
                report,
                preview,
                transition,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                definitions,
                selections[:-1],
            )

        duplicate = (*selections, selections[0])
        with self.assertRaisesRegex(ValueError, "duplicate tool-selection proposal"):
            build_future_security_retest_tool_selection_proposal(
                review,
                preflight,
                request,
                plan,
                report,
                preview,
                transition,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                definitions,
                duplicate,
            )

    def test_non_candidate_tool_fails_closed(self):
        *base, definitions, selections = self._inputs(
            suffix="tool-selection-noncandidate"
        )
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
        ) = base
        invalid = (
            FutureSecurityRetestToolSelectionProposalItem(
                capability_id=selections[0].capability_id,
                proposed_tool_id="not-admitted",
            ),
            *selections[1:],
        )
        with self.assertRaisesRegex(ValueError, "not an admitted candidate"):
            build_future_security_retest_tool_selection_proposal(
                review,
                preflight,
                request,
                plan,
                report,
                preview,
                transition,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                definitions,
                invalid,
            )

    def test_catalog_gap_cannot_produce_selection_proposal(self):
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
        ) = self.r._inputs(suffix="tool-selection-gap")

        gap_review = review_tests.build_future_security_retest_tool_policy_catalog_review(
            preflight,
            request,
            plan,
            report,
            preview,
            transition,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            (),
        )

        with self.assertRaisesRegex(ValueError, "gap-free candidate metadata"):
            build_future_security_retest_tool_selection_proposal(
                gap_review,
                preflight,
                request,
                plan,
                report,
                preview,
                transition,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                (),
                (),
            )

    def test_tampered_review_is_rejected_by_live_revalidation(self):
        *base, definitions, selections = self._inputs(
            suffix="tool-selection-tamper"
        )
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
        ) = base
        tampered = dataclasses.replace(review, review_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "catalog review is stale"):
            build_future_security_retest_tool_selection_proposal(
                tampered,
                preflight,
                request,
                plan,
                report,
                preview,
                transition,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
                definitions,
                selections,
            )

    def test_proposal_is_deterministic_and_json_serializable(self):
        *base, definitions, selections = self._inputs(
            suffix="tool-selection-deterministic"
        )
        (
            current,
            transition,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            preflight,
            review,
        ) = base
        before = dataclasses.asdict(current)

        first = build_future_security_retest_tool_selection_proposal(
            review,
            preflight,
            request,
            plan,
            report,
            preview,
            transition,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            definitions,
            selections,
        )
        second = build_future_security_retest_tool_selection_proposal(
            review,
            preflight,
            request,
            plan,
            report,
            preview,
            transition,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
            definitions,
            tuple(reversed(selections)),
        )

        self.assertEqual(first, second)
        self.assertEqual(len(first.proposal_sha256), 64)
        int(first.proposal_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["proposal_sha256"], first.proposal_sha256)
        self.assertEqual(exported["selection_authorized"], False)
        self.assertEqual(exported["tool_call_created"], False)
        self.assertEqual(exported["arguments_resolved"], False)
        self.assertEqual(exported["execution_allowed"], False)


if __name__ == "__main__":
    unittest.main()
