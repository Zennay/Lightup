from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_graph_diff_preview as preview_tests
from lightup.future_attack_path_graph_diff_policy import (
    GraphDiffPolicyDisposition,
    decide_future_attack_path_graph_diff_policy,
)
from lightup.future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    build_future_attack_path_graph_diff_preview,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_effects import RiskDirection


class FutureAttackPathGraphDiffPolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = preview_tests.FutureAttackPathGraphDiffPreviewTest(
            "test_introduced_preview_is_deterministic_and_read_only"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _decision(self, classification, *, suffix):
        proposal, context, resolution = self.p._resolved_preview_input(
            classification,
            suffix=suffix,
        )
        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        decision = decide_future_attack_path_graph_diff_policy(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return proposal, context, resolution, preview, decision

    def test_validated_introduced_preview_is_deterministic_and_review_eligible(self):
        current = self.p.r.t.f.f.current
        before = dataclasses.asdict(current)
        proposal, context, resolution, preview, first = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-introduced",
        )
        second = decide_future_attack_path_graph_diff_policy(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first.disposition,
            GraphDiffPolicyDisposition.ELIGIBLE_FOR_OPERATOR_REVIEW,
        )
        self.assertEqual(first.reason_codes, ("validated_preview",))
        self.assertEqual(first.preview_sha256, preview.preview_sha256)
        self.assertEqual(first.proposal_sha256, preview.proposal_sha256)
        self.assertEqual(
            first.impact_analysis_sha256,
            preview.impact_analysis_sha256,
        )
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")
        self.assertEqual(len(first.decision_sha256), 64)
        int(first.decision_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

    def test_insufficient_evidence_fails_closed_into_more_evidence(self):
        _, _, _, preview, decision = self._decision(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="policy-insufficient",
        )

        self.assertTrue(preview.contains_insufficient_evidence)
        self.assertEqual(
            decision.disposition,
            GraphDiffPolicyDisposition.REQUIRES_MORE_EVIDENCE,
        )
        self.assertEqual(decision.reason_codes, ("insufficient_evidence",))
        self.assertNotEqual(
            decision.disposition,
            GraphDiffPolicyDisposition.ELIGIBLE_FOR_OPERATOR_REVIEW,
        )

    def test_every_evidence_complete_preview_action_is_review_metadata_only(self):
        cases = (
            (
                AttackPathTransitionClassification.WORSENED,
                RiskDirection.INCREASED,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
                "worsened",
            ),
            (
                AttackPathTransitionClassification.IMPROVED,
                RiskDirection.DECREASED,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
                "improved",
            ),
            (
                AttackPathTransitionClassification.REMOVED,
                RiskDirection.DECREASED,
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
                "removed",
            ),
        )
        for classification, direction, expected_action, suffix in cases:
            with self.subTest(classification=classification.value):
                current, proposal, context, resolution = (
                    self.p._existing_path_resolved_preview_input(
                        classification,
                        direction=direction,
                        suffix=f"policy-{suffix}",
                    )
                )
                before = dataclasses.asdict(current)
                preview = build_future_attack_path_graph_diff_preview(
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )
                decision = decide_future_attack_path_graph_diff_policy(
                    preview,
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )

                self.assertEqual(preview.items[0].action, expected_action)
                self.assertEqual(
                    decision.disposition,
                    GraphDiffPolicyDisposition.ELIGIBLE_FOR_OPERATOR_REVIEW,
                )
                self.assertFalse(decision.attack_path_mutation_allowed)
                self.assertEqual(decision.security_verdict, "not_evaluated")
                self.assertEqual(decision.future_semantics, "unresolved")
                self.assertEqual(dataclasses.asdict(current), before)

    def test_tampered_preview_digest_is_rejected(self):
        proposal, context, resolution, preview, _ = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-tampered-digest",
        )
        tampered = dataclasses.replace(preview, preview_sha256="0" * 64)

        with self.assertRaisesRegex(
            ValueError,
            "stale, tampered, cross-tenant, or lineage-drifted",
        ):
            decide_future_attack_path_graph_diff_policy(
                tampered,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_cross_tenant_preview_is_rejected(self):
        proposal, context, resolution, preview, _ = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-cross-tenant",
        )
        foreign = dataclasses.replace(preview, client_id="client-foreign")

        with self.assertRaisesRegex(
            ValueError,
            "stale, tampered, cross-tenant, or lineage-drifted",
        ):
            decide_future_attack_path_graph_diff_policy(
                foreign,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_missing_lineage_is_rejected_before_policy_decision(self):
        proposal, context, resolution, preview, _ = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-missing-lineage",
        )
        item = dataclasses.replace(preview.items[0], resolution_sha256="")
        malformed = dataclasses.replace(preview, items=(item,))

        with self.assertRaisesRegex(ValueError, "resolution_sha256"):
            decide_future_attack_path_graph_diff_policy(
                malformed,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_missing_effect_evidence_or_capability_lineage_is_rejected(self):
        proposal, context, resolution, preview, _ = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-empty-lineage",
        )
        cases = (
            ("effect_ids", dataclasses.replace(preview.items[0], effect_ids=())),
            ("evidence_ids", dataclasses.replace(preview.items[0], evidence_ids=())),
            ("capability_ids", dataclasses.replace(preview.items[0], capability_ids=())),
        )
        for expected_name, item in cases:
            with self.subTest(expected_name=expected_name):
                malformed = dataclasses.replace(preview, items=(item,))
                with self.assertRaisesRegex(ValueError, expected_name):
                    decide_future_attack_path_graph_diff_policy(
                        malformed,
                        proposal,
                        (resolution,),
                        (context,),
                        self.state,
                    )

    def test_unsupported_action_is_rejected_before_policy_decision(self):
        proposal, context, resolution, preview, _ = self._decision(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="policy-unsupported-action",
        )
        item = dataclasses.replace(preview.items[0], action="execute_graph_change")
        malformed = dataclasses.replace(preview, items=(item,))

        with self.assertRaisesRegex(ValueError, "unsupported action"):
            decide_future_attack_path_graph_diff_policy(
                malformed,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_duplicate_current_path_lineage_is_rejected(self):
        current, proposal, context, resolution = (
            self.p._existing_path_resolved_preview_input(
                AttackPathTransitionClassification.WORSENED,
                direction=RiskDirection.INCREASED,
                suffix="policy-duplicate-path",
            )
        )
        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        path_id = preview.items[0].current_attack_path_ids[0]
        item = dataclasses.replace(
            preview.items[0],
            current_attack_path_ids=(path_id, path_id),
        )
        malformed = dataclasses.replace(preview, items=(item,))

        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            decide_future_attack_path_graph_diff_policy(
                malformed,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_rejected_disposition_is_explicitly_reserved_in_contract(self):
        self.assertEqual(
            GraphDiffPolicyDisposition.REJECTED.value,
            "rejected",
        )


if __name__ == "__main__":
    unittest.main()
