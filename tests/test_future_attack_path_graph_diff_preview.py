from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_transition_resolution as resolution_tests
from lightup.ai.orchestration import RunContext
from lightup.future_attack_path_analysis import analyze_future_attack_path_impact
from lightup.future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    build_future_attack_path_graph_diff_preview,
)
from lightup.future_attack_path_transition import propose_future_attack_path_transitions
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    verify_future_attack_path_transition,
)
from lightup.future_effects import RiskDirection
from lightup.twin import AttackPath, AttackStep


class FutureAttackPathGraphDiffPreviewTest(unittest.TestCase):
    def setUp(self):
        self.r = resolution_tests.FutureAttackPathTransitionResolutionTest(
            "test_introduced_requires_and_accepts_fresh_lab_evidence"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _resolved_preview_input(
        self,
        classification: AttackPathTransitionClassification,
        *,
        suffix: str,
    ):
        proposal = self.r._proposal(suffix=suffix)
        context, evidence_id = self.r._fresh_lab_evidence(
            proposal,
            classification,
            suffix=suffix,
        )
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )
        return proposal, context, resolution

    def _existing_path_resolved_preview_input(
        self,
        classification: AttackPathTransitionClassification,
        *,
        direction: RiskDirection,
        suffix: str,
    ):
        graph_fixture = self.r.t.f.f
        path_id = f"path-preview-{suffix}"
        path = AttackPath(
            path_id=path_id,
            title=f"Existing path {suffix}",
            steps=(
                AttackStep(
                    source_id=graph_fixture.subject.node_id,
                    target_id=graph_fixture.subject.node_id,
                    relation="existing_self_reference",
                ),
            ),
            evidence_refs=(f"evidence:{path_id}",),
        )
        current = graph_fixture.current.next_snapshot(
            attack_paths=graph_fixture.current.attack_paths + (path,)
        )
        resolved = self.r.t.f._resolved_from_current(
            current,
            graph_id=f"graph-preview-{suffix}",
            direction=direction,
        )
        report = analyze_future_attack_path_impact(
            resolved,
            self.state,
            self.r.t.f.client,
            current=current,
        )
        proposal = propose_future_attack_path_transitions(report)
        self.assertEqual(
            proposal.items[0].current_attack_path_ids,
            (path_id,),
        )
        context, evidence_id = self.r._fresh_lab_evidence(
            proposal,
            classification,
            suffix=suffix,
        )
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )
        return current, proposal, context, resolution

    def test_introduced_preview_is_deterministic_and_read_only(self):
        proposal, context, resolution = self._resolved_preview_input(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="preview-introduced",
        )
        current = self.r.t.f.f.current
        before = dataclasses.asdict(current)

        first = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        second = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertEqual(first, second)
        self.assertTrue(first.preview_complete)
        self.assertFalse(first.contains_insufficient_evidence)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.security_verdict, "not_evaluated")
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(
            first.items[0].action,
            AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
        )
        self.assertEqual(first.items[0].current_attack_path_ids, ())
        self.assertEqual(len(first.preview_sha256), 64)
        int(first.preview_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

    def test_existing_path_classifications_map_to_read_only_actions(self):
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
                    self._existing_path_resolved_preview_input(
                        classification,
                        direction=direction,
                        suffix=suffix,
                    )
                )
                before = dataclasses.asdict(current)

                preview = build_future_attack_path_graph_diff_preview(
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )

                self.assertTrue(preview.preview_complete)
                self.assertFalse(preview.contains_insufficient_evidence)
                self.assertEqual(preview.items[0].action, expected_action)
                self.assertEqual(
                    preview.items[0].current_attack_path_ids,
                    proposal.items[0].current_attack_path_ids,
                )
                self.assertFalse(preview.attack_path_mutation_allowed)
                self.assertEqual(preview.security_verdict, "not_evaluated")
                self.assertEqual(preview.future_semantics, "unresolved")
                self.assertEqual(dataclasses.asdict(current), before)

    def test_insufficient_evidence_produces_no_graph_change_claim(self):
        proposal, context, resolution = self._resolved_preview_input(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="preview-insufficient",
        )

        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertTrue(preview.preview_complete)
        self.assertTrue(preview.contains_insufficient_evidence)
        self.assertEqual(
            preview.items[0].action,
            AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
        )
        self.assertFalse(preview.attack_path_mutation_allowed)
        self.assertEqual(preview.security_verdict, "not_evaluated")

    def test_requires_exact_resolution_coverage(self):
        proposal, context, resolution = self._resolved_preview_input(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="preview-coverage",
        )

        with self.assertRaisesRegex(ValueError, "exactly one resolution"):
            build_future_attack_path_graph_diff_preview(
                proposal,
                (),
                (),
                self.state,
            )

        with self.assertRaisesRegex(ValueError, "exactly one resolution"):
            build_future_attack_path_graph_diff_preview(
                proposal,
                (resolution, resolution),
                (context,),
                self.state,
            )

    def test_contexts_must_exactly_cover_resolution_runs(self):
        proposal, context, resolution = self._resolved_preview_input(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="preview-context",
        )
        extra_run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        extra_context = RunContext.for_lab(
            extra_run_id,
            engagement_id="preview-extra-context",
            client_id="client-1",
        )

        with self.assertRaisesRegex(ValueError, "contexts must exactly cover"):
            build_future_attack_path_graph_diff_preview(
                proposal,
                (resolution,),
                (context, extra_context),
                self.state,
            )

    def test_mutable_input_collections_are_rejected(self):
        proposal, context, resolution = self._resolved_preview_input(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="preview-mutable",
        )

        with self.assertRaisesRegex(ValueError, "resolutions must be an immutable tuple"):
            build_future_attack_path_graph_diff_preview(
                proposal,
                [resolution],
                (context,),
                self.state,
            )
        with self.assertRaisesRegex(ValueError, "contexts must be an immutable tuple"):
            build_future_attack_path_graph_diff_preview(
                proposal,
                (resolution,),
                [context],
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
