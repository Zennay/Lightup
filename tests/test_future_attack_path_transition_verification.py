from __future__ import annotations

import dataclasses
import hashlib
import unittest

import test_future_attack_path_transition as proposal_tests
from lightup.ai.orchestration import RunContext
from lightup.future_attack_path_transition import (
    propose_future_attack_path_transitions,
)
from lightup.future_attack_path_transition_verification import (
    AttackPathTransitionClassification,
    _validate_action_classification,
    validate_future_attack_path_transition_resolution,
    verify_future_attack_path_transition,
)
from lightup.future_effects import RiskDirection


class FutureAttackPathTransitionVerificationTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureAttackPathTransitionProposalTest(
            "test_regression_without_current_path_is_hypothesis_review_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.f.f.state

    def _proposal(self, direction: RiskDirection, *, suffix: str):
        report = self.base._report(direction, suffix=suffix)
        return propose_future_attack_path_transitions(report)

    def _lab_context(self, *, engagement_id: str = "transition-verification"):
        run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        return RunContext.for_lab(
            run_id,
            engagement_id=engagement_id,
            client_id="client-1",
        )

    def _evidence(
        self,
        proposal,
        *,
        resolution_id: str,
        classification: AttackPathTransitionClassification,
        context: RunContext,
        capability_id: str = "web",
        metadata_overrides: dict[str, str] | None = None,
        payload: bytes = b'{"verified":true}',
    ) -> str:
        item = proposal.items[0]
        metadata = {
            "purpose": "future_attack_path_transition_verification",
            "resolution_id": resolution_id,
            "proposal_sha256": proposal.proposal_sha256,
            "impact_analysis_sha256": proposal.impact_analysis_sha256,
            "client_id": proposal.client_id,
            "engagement_id": context.engagement_id,
            "mode": context.mode.value,
            "is_lab": "true",
            "change_node_id": item.change_node_id,
            "subject_node_id": item.subject_node_id,
            "classification": classification.value,
            "effect_ids_sha256": hashlib.sha256(
                "\x1f".join(item.effect_ids).encode("utf-8")
            ).hexdigest(),
            "current_attack_path_ids_sha256": hashlib.sha256(
                "\x1f".join(item.current_attack_path_ids).encode("utf-8")
            ).hexdigest(),
        }
        metadata.update(metadata_overrides or {})
        return self.state.add_evidence(
            context.run_id,
            capability_id,
            "future-attack-path-transition-verification",
            "isolated-lab-fixture",
            payload,
            metadata=metadata,
        )

    def test_new_path_hypothesis_can_be_verified_as_introduced_with_fresh_lab_evidence(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="introduced")
        self.assertEqual(
            proposal.items[0].review_action,
            "review_new_path_hypothesis",
        )
        context = self._lab_context()
        resolution_id = "transition-resolution-introduced"
        evidence_id = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
        )

        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            resolution_id=resolution_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )

        self.assertEqual(resolution.classification, "introduced")
        self.assertEqual(resolution.proposal_sha256, proposal.proposal_sha256)
        self.assertEqual(
            resolution.impact_analysis_sha256,
            proposal.impact_analysis_sha256,
        )
        self.assertEqual(resolution.effect_ids, proposal.items[0].effect_ids)
        self.assertEqual(resolution.current_attack_path_ids, ())
        self.assertFalse(resolution.attack_path_mutation_allowed)
        self.assertEqual(resolution.security_verdict, "not_evaluated")
        self.assertEqual(resolution.future_semantics, "unresolved")
        validate_future_attack_path_transition_resolution(
            resolution,
            proposal,
            context,
            self.state,
        )

    def test_action_classification_compatibility_table_fails_closed(self):
        allowed = {
            "review_new_path_hypothesis": {"introduced", "insufficient_evidence"},
            "review_existing_paths_for_regression": {"worsened", "insufficient_evidence"},
            "review_existing_paths_for_improvement": {
                "improved",
                "removed",
                "insufficient_evidence",
            },
            "review_improvement_without_path_claim": {"insufficient_evidence"},
            "no_transition_claim": {"insufficient_evidence"},
            "manual_transition_review": {
                "introduced",
                "removed",
                "worsened",
                "improved",
                "insufficient_evidence",
            },
        }
        all_classifications = {item.value for item in AttackPathTransitionClassification}
        for action, allowed_values in allowed.items():
            for classification in all_classifications:
                with self.subTest(action=action, classification=classification):
                    if classification in allowed_values:
                        _validate_action_classification(action, classification)
                    else:
                        with self.assertRaisesRegex(ValueError, "incompatible"):
                            _validate_action_classification(action, classification)

    def test_incompatible_classification_is_rejected_before_evidence_read(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="bad-classification")
        context = self._lab_context()

        with self.assertRaisesRegex(ValueError, "incompatible"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.WORSENED,
                resolution_id="transition-resolution-bad-classification",
                evidence_ids=("does-not-exist",),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_resolution_requires_lab_autonomous_context(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="non-lab")
        context = self._lab_context()
        resolution_id = "transition-resolution-non-lab"
        evidence_id = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
        )
        forged = dataclasses.replace(context, is_lab=False)

        with self.assertRaisesRegex(PermissionError, "LAB_AUTONOMOUS"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.INTRODUCED,
                resolution_id=resolution_id,
                evidence_ids=(evidence_id,),
                capability_ids=("web",),
                context=forged,
                state=self.state,
            )

    def test_proposal_evidence_cannot_be_reused_as_transition_evidence(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="freshness")
        existing_refs = [
            ref[len("evidence:"):]
            for ref in proposal.items[0].evidence_refs
            if ref.startswith("evidence:")
        ]
        self.assertTrue(existing_refs)
        context = self._lab_context()

        with self.assertRaisesRegex(ValueError, "must be fresh"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.INTRODUCED,
                resolution_id="transition-resolution-reused",
                evidence_ids=(existing_refs[0],),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_evidence_metadata_must_bind_exact_proposal_item_and_context(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="metadata")
        context = self._lab_context()
        resolution_id = "transition-resolution-metadata"
        bad = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
            metadata_overrides={"subject_node_id": "forged-subject"},
        )

        with self.assertRaisesRegex(ValueError, "subject_node_id"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.INTRODUCED,
                resolution_id=resolution_id,
                evidence_ids=(bad,),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_capabilities_must_exactly_match_fresh_evidence(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="capabilities")
        context = self._lab_context()
        resolution_id = "transition-resolution-capabilities"
        evidence_id = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
            capability_id="web",
        )

        with self.assertRaisesRegex(ValueError, "exactly match fresh evidence"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.INTRODUCED,
                resolution_id=resolution_id,
                evidence_ids=(evidence_id,),
                capability_ids=("cloud",),
                context=context,
                state=self.state,
            )

    def test_exact_replay_is_idempotent_but_changed_resolution_id_semantics_collide(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="idempotency")
        context = self._lab_context()
        resolution_id = "transition-resolution-idempotent"
        first_evidence = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
            payload=b"first",
        )
        first = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            resolution_id=resolution_id,
            evidence_ids=(first_evidence,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )
        repeated = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            resolution_id=resolution_id,
            evidence_ids=(first_evidence,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )
        self.assertEqual(repeated, first)

        second_evidence = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            context=context,
            payload=b"second",
        )
        with self.assertRaisesRegex(ValueError, "resolution ID collision"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
                resolution_id=resolution_id,
                evidence_ids=(second_evidence,),
                capability_ids=("web",),
                context=context,
                state=self.state,
            )

    def test_deleted_evidence_is_rejected_on_revalidation(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="deleted")
        context = self._lab_context()
        resolution_id = "transition-resolution-deleted"
        evidence_id = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
        )
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            resolution_id=resolution_id,
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
                resolution,
                proposal,
                context,
                self.state,
            )

    def test_tampered_resolution_digest_or_boundary_is_rejected(self):
        proposal = self._proposal(RiskDirection.INCREASED, suffix="tamper")
        context = self._lab_context()
        resolution_id = "transition-resolution-tamper"
        evidence_id = self._evidence(
            proposal,
            resolution_id=resolution_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            context=context,
        )
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=AttackPathTransitionClassification.INTRODUCED,
            resolution_id=resolution_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.state,
        )

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_future_attack_path_transition_resolution(
                dataclasses.replace(resolution, resolution_sha256="0" * 64),
                proposal,
                context,
                self.state,
            )
        with self.assertRaisesRegex(ValueError, "cannot claim a security verdict"):
            validate_future_attack_path_transition_resolution(
                dataclasses.replace(resolution, security_verdict="approved"),
                proposal,
                context,
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
