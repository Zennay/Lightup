from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_transition as transition_tests
from lightup.ai.orchestration import RunContext
from lightup.future_attack_path_transition import propose_future_attack_path_transitions
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    future_attack_path_transition_evidence_contract,
    validate_future_attack_path_transition_resolution,
    verify_future_attack_path_transition,
)
from lightup.future_effects import RiskDirection


class FutureAttackPathTransitionResolutionTest(unittest.TestCase):
    def setUp(self):
        self.t = transition_tests.FutureAttackPathTransitionProposalTest(
            "test_regression_without_current_path_is_hypothesis_review_only"
        )
        self.t.setUp()
        self.addCleanup(self.t.tearDown)
        self.state = self.t.f.f.state

    def _proposal(
        self,
        direction: RiskDirection = RiskDirection.INCREASED,
        *,
        suffix: str,
    ):
        report = self.t._report(direction, suffix=suffix)
        return propose_future_attack_path_transitions(report)

    def _fresh_lab_evidence(
        self,
        proposal,
        classification: AttackPathTransitionClassification,
        *,
        suffix: str,
        capability_id: str = "web",
        metadata_updates: dict[str, str] | None = None,
        evidence_run_id: str | None = None,
    ):
        run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        context = RunContext.for_lab(
            run_id,
            engagement_id=f"transition-{suffix}",
            client_id="client-1",
        )
        item = proposal.items[0]
        metadata = future_attack_path_transition_evidence_contract(
            proposal,
            change_node_id=item.change_node_id,
            classification=classification,
            context=context,
        )
        if metadata_updates:
            metadata.update(metadata_updates)
        stored_run_id = evidence_run_id or run_id
        evidence_id = self.state.add_evidence(
            stored_run_id,
            capability_id,
            "future-transition-verification",
            "isolated-lab-fixture",
            f"fresh transition proof {suffix}".encode("utf-8"),
            metadata=metadata,
        )
        return context, evidence_id

    def test_introduced_requires_and_accepts_fresh_lab_evidence(self):
        proposal = self._proposal(suffix="introduced")
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="introduced",
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

        self.assertEqual(resolution.classification, classification)
        self.assertEqual(resolution.proposal_sha256, proposal.proposal_sha256)
        self.assertEqual(
            resolution.impact_analysis_sha256,
            proposal.impact_analysis_sha256,
        )
        self.assertFalse(resolution.attack_path_mutation_allowed)
        self.assertEqual(resolution.security_verdict, "not_evaluated")
        self.assertEqual(len(resolution.resolution_sha256), 64)

    def test_exact_replay_is_deterministic(self):
        proposal = self._proposal(suffix="replay")
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="replay",
        )
        kwargs = dict(
            proposal=proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )

        first = verify_future_attack_path_transition(**kwargs)
        second = verify_future_attack_path_transition(**kwargs)
        self.assertEqual(first, second)

    def test_reusing_st3_evidence_is_rejected_before_lookup(self):
        proposal = self._proposal(suffix="reuse")
        item = proposal.items[0]
        old_evidence = next(
            ref[len("evidence:") :]
            for ref in item.evidence_refs
            if ref.startswith("evidence:")
        )
        run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        context = RunContext.for_lab(
            run_id,
            engagement_id="transition-reuse",
            client_id="client-1",
        )

        with self.assertRaisesRegex(ValueError, "fresh evidence"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=item.change_node_id,
                classification=AttackPathTransitionClassification.INTRODUCED,
                run_id=run_id,
                evidence_ids=(old_evidence,),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_action_classification_mapping_fails_closed(self):
        proposal = self._proposal(suffix="mapping")
        item = proposal.items[0]

        with self.assertRaisesRegex(ValueError, "incompatible"):
            future_attack_path_transition_evidence_contract(
                proposal,
                change_node_id=item.change_node_id,
                classification=AttackPathTransitionClassification.WORSENED,
                context=RunContext.for_lab(
                    self.state.create_run(
                        "127.0.0.1",
                        activation_mode="lab_autonomous",
                    ),
                    engagement_id="transition-mapping",
                    client_id="client-1",
                ),
            )

    def test_cross_run_evidence_is_rejected(self):
        proposal = self._proposal(suffix="cross-run")
        classification = AttackPathTransitionClassification.INTRODUCED
        other_run = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="cross-run",
            evidence_run_id=other_run,
        )

        with self.assertRaisesRegex(ValueError, "another run"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=(evidence_id,),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_evidence_metadata_and_capability_must_match_exactly(self):
        proposal = self._proposal(suffix="metadata")
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="metadata",
            metadata_updates={"proposal_sha256": "0" * 64},
        )

        with self.assertRaisesRegex(ValueError, "metadata mismatch for proposal_sha256"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=(evidence_id,),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

        clean_context, clean_evidence = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="capability",
            capability_id="web",
        )
        with self.assertRaisesRegex(ValueError, "capability_ids must exactly match"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=clean_context.run_id,
                evidence_ids=(clean_evidence,),
                capability_ids=("tls",),
                context=clean_context,
                state=self.state,
            )

    def test_deleted_evidence_fails_live_revalidation(self):
        proposal = self._proposal(suffix="deleted")
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="deleted",
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
        with self.state.connect() as connection:
            connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (evidence_id,),
            )

        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            validate_future_attack_path_transition_resolution(
                proposal,
                resolution,
                context,
                self.state,
            )

    def test_tampered_resolution_digest_and_identity_fail_closed(self):
        proposal = self._proposal(suffix="tamper")
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self._fresh_lab_evidence(
            proposal,
            classification,
            suffix="tamper",
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

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_future_attack_path_transition_resolution(
                proposal,
                dataclasses.replace(resolution, resolution_sha256="0" * 64),
                context,
                self.state,
            )
        with self.assertRaisesRegex(ValueError, "non-canonical stable id"):
            validate_future_attack_path_transition_resolution(
                proposal,
                dataclasses.replace(
                    resolution,
                    resolution_id="transition-resolution:" + "0" * 24,
                ),
                context,
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
