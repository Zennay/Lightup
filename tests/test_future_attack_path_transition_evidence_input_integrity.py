from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_transition_resolution as resolution_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    validate_future_attack_path_transition_resolution,
    verify_future_attack_path_transition,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class TransitionEvidenceInputIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.r = resolution_tests.FutureAttackPathTransitionResolutionTest(
            "test_introduced_requires_and_accepts_fresh_lab_evidence"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def _fixture(self, suffix: str):
        proposal = self.r._proposal(suffix=suffix)
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self.r._fresh_lab_evidence(
            proposal,
            classification,
            suffix=suffix,
        )
        return proposal, classification, context, evidence_id

    def _verify(self, suffix: str, evidence_ids):
        proposal, classification, context, _ = self._fixture(suffix)
        return verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=evidence_ids,
            capability_ids=("web",),
            context=context,
            state=self.r.state,
        )

    def test_exact_tuple_with_exact_string_remains_green(self):
        proposal, classification, context, evidence_id = self._fixture("canonical")

        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.r.state,
        )

        self.assertEqual(resolution.evidence_ids, (evidence_id,))

    def test_builder_rejects_list_before_normalization(self):
        proposal, classification, context, evidence_id = self._fixture("list")

        with self.assertRaisesRegex(ValueError, "evidence_ids.*exact tuple"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=[evidence_id],
                capability_ids=("web",),
                context=context,
                state=self.r.state,
            )

    def test_builder_rejects_tuple_subclass_before_normalization(self):
        proposal, classification, context, evidence_id = self._fixture("tuple-subclass")

        with self.assertRaisesRegex(ValueError, "evidence_ids.*exact tuple"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=_EvidenceTuple((evidence_id,)),
                capability_ids=("web",),
                context=context,
                state=self.r.state,
            )

    def test_builder_rejects_string_subclass_before_normalization(self):
        proposal, classification, context, evidence_id = self._fixture("string-subclass")

        with self.assertRaisesRegex(ValueError, "evidence_ids.*exact strings"):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=(_EvidenceText(evidence_id),),
                capability_ids=("web",),
                context=context,
                state=self.r.state,
            )

    def test_live_revalidation_rejects_tuple_subclass_even_with_same_digest(self):
        proposal, classification, context, evidence_id = self._fixture("live-tuple")
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.r.state,
        )
        forged = dataclasses.replace(
            resolution,
            evidence_ids=_EvidenceTuple(resolution.evidence_ids),
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids.*exact tuple"):
            validate_future_attack_path_transition_resolution(
                proposal,
                forged,
                context,
                self.r.state,
            )

    def test_live_revalidation_rejects_string_subclass_even_with_same_digest(self):
        proposal, classification, context, evidence_id = self._fixture("live-string")
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.r.state,
        )
        forged = dataclasses.replace(
            resolution,
            evidence_ids=(_EvidenceText(evidence_id),),
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids.*exact strings"):
            validate_future_attack_path_transition_resolution(
                proposal,
                forged,
                context,
                self.r.state,
            )


if __name__ == "__main__":
    unittest.main()
