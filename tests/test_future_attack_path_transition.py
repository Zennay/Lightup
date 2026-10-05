from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_analysis as impact_tests
from lightup.future_attack_path_analysis import analyze_future_attack_path_impact
from lightup.future_attack_path_transition import (
    future_attack_path_transition_proposal_from_dict,
    propose_future_attack_path_transitions,
    validate_future_attack_path_transition_proposal,
)
from lightup.future_effects import RiskDirection
from lightup.twin import AttackPath, AttackStep


class FutureAttackPathTransitionProposalTest(unittest.TestCase):
    def setUp(self):
        self.f = impact_tests.FutureAttackPathImpactAnalysisTest(
            "test_analysis_digest_is_stable_and_binds_exact_impact_semantics"
        )
        self.f.setUp()
        self.addCleanup(self.f.tearDown)

    def _report(self, direction: RiskDirection, *, suffix: str):
        effect = self.f._effect(f"effect-transition-{suffix}", direction)
        resolved = self.f._resolved_with(
            (effect,),
            graph_id=f"graph-transition-{suffix}",
        )
        return analyze_future_attack_path_impact(
            resolved,
            self.f.f.state,
            self.f.client,
            current=self.f.f.current,
        )

    def test_regression_without_current_path_is_hypothesis_review_only(self):
        report = self._report(RiskDirection.INCREASED, suffix="new-path")
        proposal = propose_future_attack_path_transitions(report)

        self.assertTrue(proposal.proposal_complete)
        self.assertFalse(proposal.attack_path_mutation_allowed)
        self.assertEqual(proposal.security_verdict, "not_evaluated")
        self.assertEqual(proposal.future_semantics, "unresolved")
        self.assertEqual(proposal.impact_analysis_sha256, report.analysis_sha256)
        self.assertEqual(
            proposal.items[0].review_action,
            "review_new_path_hypothesis",
        )
        self.assertEqual(proposal.items[0].current_attack_path_ids, ())

    def test_regression_with_existing_path_reviews_only_that_path(self):
        path = AttackPath(
            path_id="path-transition-existing",
            title="Existing path",
            steps=(
                AttackStep(
                    source_id=self.f.f.subject.node_id,
                    target_id=self.f.f.subject.node_id,
                    relation="existing_self_reference",
                ),
            ),
            evidence_refs=("evidence:existing-path",),
        )
        current = self.f.f.current.next_snapshot(
            attack_paths=self.f.f.current.attack_paths + (path,)
        )
        resolved = self.f._resolved_from_current(
            current,
            graph_id="graph-transition-existing",
        )
        report = analyze_future_attack_path_impact(
            resolved,
            self.f.f.state,
            self.f.client,
            current=current,
        )
        before = current.attack_paths
        proposal = propose_future_attack_path_transitions(report)

        self.assertEqual(
            proposal.items[0].review_action,
            "review_existing_paths_for_regression",
        )
        self.assertEqual(
            proposal.items[0].current_attack_path_ids,
            ("path-transition-existing",),
        )
        self.assertEqual(current.attack_paths, before)

    def test_conservative_impact_mappings(self):
        cases = (
            (
                RiskDirection.DECREASED,
                "review_improvement_without_path_claim",
                "improvement",
            ),
            (
                RiskDirection.UNCHANGED,
                "no_transition_claim",
                "unchanged",
            ),
        )
        for direction, action, suffix in cases:
            with self.subTest(direction=direction.value):
                report = self._report(direction, suffix=suffix)
                proposal = propose_future_attack_path_transitions(report)
                self.assertEqual(proposal.items[0].review_action, action)

        decreased = self.f._effect(
            "effect-transition-mixed-decreased",
            RiskDirection.DECREASED,
        )
        mixed = self.f._resolved_with(
            (self.f.f.effect, decreased),
            graph_id="graph-transition-mixed",
        )
        mixed_report = analyze_future_attack_path_impact(
            mixed,
            self.f.f.state,
            self.f.client,
            current=self.f.f.current,
        )
        mixed_proposal = propose_future_attack_path_transitions(mixed_report)
        self.assertEqual(
            mixed_proposal.items[0].review_action,
            "manual_transition_review",
        )

    def test_proposal_digest_is_deterministic_and_binds_source_analysis(self):
        report = self._report(RiskDirection.INCREASED, suffix="digest")
        first = propose_future_attack_path_transitions(report)
        second = propose_future_attack_path_transitions(report)

        self.assertEqual(first, second)
        self.assertEqual(len(first.proposal_sha256), 64)
        int(first.proposal_sha256, 16)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(first, proposal_sha256="0" * 64)
            )

    def test_tampered_impact_handoff_is_rejected_before_proposal(self):
        report = self._report(RiskDirection.INCREASED, suffix="tampered-source")
        with self.assertRaisesRegex(ValueError, "report digest mismatch"):
            propose_future_attack_path_transitions(
                dataclasses.replace(report, analysis_sha256="0" * 64)
            )

    def test_proposal_identity_versions_and_digests_fail_closed(self):
        report = self._report(RiskDirection.INCREASED, suffix="identity")
        proposal = propose_future_attack_path_transitions(report)

        invalid_cases = (
            dataclasses.replace(proposal, client_id=""),
            dataclasses.replace(proposal, current_twin_version=0),
            dataclasses.replace(proposal, twin_version=True),
            dataclasses.replace(proposal, impact_analysis_sha256="not-a-digest"),
            dataclasses.replace(proposal, proposal_sha256="g" * 64),
        )
        for invalid in invalid_cases:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_future_attack_path_transition_proposal(invalid)

    def test_serialized_proposal_round_trip_is_strict_and_validated(self):
        report = self._report(RiskDirection.INCREASED, suffix="round-trip")
        proposal = propose_future_attack_path_transitions(report)
        payload = __import__("json").loads(
            __import__("json").dumps(proposal.as_dict())
        )

        restored = future_attack_path_transition_proposal_from_dict(payload)
        self.assertEqual(restored, proposal)

        extra = dict(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_attack_path_transition_proposal_from_dict(extra)

        tampered = __import__("json").loads(__import__("json").dumps(payload))
        tampered["items"][0]["review_action"] = "create_attack_path"
        with self.assertRaises(ValueError):
            future_attack_path_transition_proposal_from_dict(tampered)

        wrong_shape = __import__("json").loads(__import__("json").dumps(payload))
        wrong_shape["items"] = {"not": "a list"}
        with self.assertRaisesRegex(ValueError, "items must be a list"):
            future_attack_path_transition_proposal_from_dict(wrong_shape)

    def test_proposal_boundary_cannot_claim_mutation_or_verdict(self):
        report = self._report(RiskDirection.INCREASED, suffix="boundary")
        proposal = propose_future_attack_path_transitions(report)

        with self.assertRaisesRegex(ValueError, "cannot allow mutation"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(
                    proposal,
                    attack_path_mutation_allowed=True,
                )
            )
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(
                    proposal,
                    security_verdict="approved",
                )
            )

        item = dataclasses.replace(
            proposal.items[0],
            review_action="create_attack_path",
        )
        with self.assertRaisesRegex(ValueError, "review action is not canonical"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(proposal, items=(item,))
            )

    def test_validator_requires_evidence_lineage(self):
        report = self._report(RiskDirection.INCREASED, suffix="evidence-lineage")
        proposal = propose_future_attack_path_transitions(report)
        item = dataclasses.replace(proposal.items[0], evidence_refs=())

        with self.assertRaisesRegex(ValueError, "requires evidence lineage"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(proposal, items=(item,))
            )

    def test_validator_rejects_duplicate_and_noncanonical_items(self):
        report = self._report(RiskDirection.INCREASED, suffix="canonical-items")
        proposal = propose_future_attack_path_transitions(report)
        item = proposal.items[0]

        with self.assertRaisesRegex(ValueError, "duplicates a change"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(proposal, items=(item, item))
            )

        later = dataclasses.replace(item, change_node_id="change:z")
        earlier = dataclasses.replace(item, change_node_id="change:a")
        with self.assertRaisesRegex(ValueError, "not canonically ordered"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(proposal, items=(later, earlier))
            )

    def test_validator_rejects_invalid_top_level_identity_version_and_hashes(self):
        report = self._report(RiskDirection.INCREASED, suffix="top-level")
        proposal = propose_future_attack_path_transitions(report)

        cases = (
            (
                dataclasses.replace(proposal, client_id=""),
                "client_id is invalid",
            ),
            (
                dataclasses.replace(proposal, current_twin_version=0),
                "current_twin_version is invalid",
            ),
            (
                dataclasses.replace(proposal, twin_version=True),
                "twin_version is invalid",
            ),
            (
                dataclasses.replace(proposal, impact_analysis_sha256="not-a-digest"),
                "impact_analysis_sha256 is not a SHA-256 digest",
            ),
            (
                dataclasses.replace(proposal, proposal_sha256="g" * 64),
                "proposal_sha256 is not a SHA-256 digest",
            ),
        )
        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    validate_future_attack_path_transition_proposal(candidate)

    def test_validator_rejects_noncanonical_or_duplicate_lineage_tuples(self):
        report = self._report(RiskDirection.INCREASED, suffix="lineage-tuples")
        proposal = propose_future_attack_path_transitions(report)
        item = proposal.items[0]

        duplicated_effects = dataclasses.replace(
            item,
            effect_ids=(item.effect_ids[0], item.effect_ids[0]),
        )
        with self.assertRaisesRegex(ValueError, "effect_ids contains duplicates"):
            validate_future_attack_path_transition_proposal(
                dataclasses.replace(proposal, items=(duplicated_effects,))
            )

        reversed_evidence = dataclasses.replace(
            item,
            evidence_refs=tuple(reversed(item.evidence_refs)),
        )
        if reversed_evidence.evidence_refs != item.evidence_refs:
            with self.assertRaisesRegex(ValueError, "evidence_refs is not canonically ordered"):
                validate_future_attack_path_transition_proposal(
                    dataclasses.replace(proposal, items=(reversed_evidence,))
                )


if __name__ == "__main__":
    unittest.main()
