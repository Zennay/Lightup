from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_transition_resolution as resolution_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    validate_future_attack_path_transition_resolution,
    verify_future_attack_path_transition,
)


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


class FutureAttackPathTransitionEvidenceIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.t = resolution_tests.FutureAttackPathTransitionResolutionTest(
            "test_introduced_requires_and_accepts_fresh_lab_evidence"
        )
        self.t.setUp()
        self.addCleanup(self.t.tearDown)

    def _fixture(self, suffix: str):
        proposal = self.t._proposal(suffix=suffix)
        classification = AttackPathTransitionClassification.INTRODUCED
        context, evidence_id = self.t._fresh_lab_evidence(
            proposal,
            classification,
            suffix=suffix,
        )
        return proposal, classification, context, evidence_id

    def _build(self, *, suffix: str, evidence_ids):
        proposal, classification, context, _ = self._fixture(suffix)
        return verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=evidence_ids,
            capability_ids=("web",),
            context=context,
            state=self.t.state,
        )

    def test_builder_rejects_non_exact_evidence_container_before_normalization(self):
        proposal, classification, context, evidence_id = self._fixture("list")
        for malformed in ([evidence_id], _TupleSubclass((evidence_id,))):
            with self.subTest(malformed_type=type(malformed).__name__):
                with self.assertRaisesRegex(
                    ValueError,
                    "evidence_ids must be an exact built-in tuple",
                ):
                    verify_future_attack_path_transition(
                        proposal,
                        change_node_id=proposal.items[0].change_node_id,
                        classification=classification,
                        run_id=context.run_id,
                        evidence_ids=malformed,
                        capability_ids=("web",),
                        context=context,
                        state=self.t.state,
                    )

    def test_builder_rejects_string_subclass_before_sorting(self):
        proposal, classification, context, evidence_id = self._fixture("string-subclass")
        with self.assertRaisesRegex(
            ValueError,
            "evidence_ids entries must be exact built-in strings",
        ):
            verify_future_attack_path_transition(
                proposal,
                change_node_id=proposal.items[0].change_node_id,
                classification=classification,
                run_id=context.run_id,
                evidence_ids=(_StringSubclass(evidence_id),),
                capability_ids=("web",),
                context=context,
                state=self.t.state,
            )

    def test_direct_revalidation_rejects_polymorphic_evidence_shape(self):
        proposal, classification, context, evidence_id = self._fixture("direct")
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.t.state,
        )

        malformed = (
            (
                dataclasses.replace(
                    resolution,
                    evidence_ids=_TupleSubclass(resolution.evidence_ids),
                ),
                "evidence_ids must be an exact built-in tuple",
            ),
            (
                dataclasses.replace(
                    resolution,
                    evidence_ids=(_StringSubclass(evidence_id),),
                ),
                "evidence_ids entries must be exact built-in strings",
            ),
        )
        for candidate, expected in malformed:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    validate_future_attack_path_transition_resolution(
                        proposal,
                        candidate,
                        context,
                        self.t.state,
                    )

    def test_canonical_exact_tuple_remains_accepted(self):
        proposal, classification, context, evidence_id = self._fixture("canonical")
        resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=context.run_id,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
            context=context,
            state=self.t.state,
        )
        self.assertIs(type(resolution.evidence_ids), tuple)
        self.assertIs(type(resolution.evidence_ids[0]), str)


if __name__ == "__main__":
    unittest.main()
