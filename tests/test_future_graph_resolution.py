from __future__ import annotations

import dataclasses
import hashlib
import unittest

import test_future_subject_resolution as subject_tests
from lightup.ai.orchestration import RunContext
from lightup.domain import AccessContext, Role
from lightup.future_binding import bind_future_change_candidates
from lightup.future_effects import (
    FutureSecurityEffect,
    RiskDirection,
    SecurityEffectKind,
    _fact_id as _effect_fact_id,
    apply_future_security_effects,
)
from lightup.future_graph_resolution import (
    FutureGraphResolution,
    apply_future_graph_resolution,
)
from lightup.future_subject_review import review_future_subjects
from lightup.future_materialization import (
    EnvironmentEquivalence,
    FutureMaterializationResolution,
    MaterializationOutcome,
    apply_future_materialization_resolution,
)
from lightup.future_subject_resolution import (
    SubjectResolutionBasis,
    apply_future_subject_resolution,
)
from lightup.twin import TwinNode, TwinNodeKind


class FutureGraphResolutionTest(subject_tests.FutureSubjectResolutionTest):
    def setUp(self):
        super().setUp()
        self.materialization_run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        self.materialization_context = RunContext.for_lab(
            self.materialization_run_id,
            engagement_id="graph-resolution-lab",
            client_id="client-1",
        )
        self.materialization_evidence_id = self.state.add_evidence(
            self.materialization_run_id,
            "web",
            "future-materialization-observation",
            "lab-fixture",
            b"isolated synthetic graph-resolution observation",
            metadata={
                "client_id": "client-1",
                "engagement_id": "graph-resolution-lab",
                "mode": "lab_autonomous",
                "is_lab": "true",
            },
        )
        self.materialization = FutureMaterializationResolution(
            resolution_id="materialization-graph-1",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            run_id=self.materialization_run_id,
            outcome=MaterializationOutcome.CONFIRMED,
            equivalence=EnvironmentEquivalence.PARTIAL,
            evidence_ids=(self.materialization_evidence_id,),
            capability_ids=("web",),
            limitations=("isolated fixture; production equivalence not claimed",),
        )
        materialized = apply_future_materialization_resolution(
            self.bound,
            self.materialization,
            self.materialization_context,
            self.state,
        )
        self.effect = FutureSecurityEffect(
            effect_id="effect-graph-1",
            resolution_id=self.materialization.resolution_id,
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            capability_id="web",
            kind=SecurityEffectKind.ATTACK_SURFACE_ADDED,
            risk_direction=RiskDirection.INCREASED,
            evidence_ids=(self.materialization_evidence_id,),
        )
        self.effected = apply_future_security_effects(
            materialized,
            self.materialization,
            (self.effect,),
        )

        self.subject_decision_id = "decision-graph-1"
        subject_evidence_id = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"exact graph subject review",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": self.subject_decision_id,
                "client_id": "client-1",
                "future_twin_id": self.effected.twin_id,
                "future_twin_version": str(self.effected.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": self.change_node.node_id,
                "subject_node_id": self.subject.node_id,
                "candidate_evidence_sha256": self.candidate_evidence_sha256,
                "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
                "rationale_sha256": hashlib.sha256(
                    self.rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        subject_resolution = dataclasses.replace(
            self.resolution,
            decision_id=self.subject_decision_id,
            evidence_ids=(subject_evidence_id,),
        )
        self.reviewed = apply_future_subject_resolution(
            self.effected,
            subject_resolution,
            self.state,
        )
        self.graph = FutureGraphResolution(
            graph_resolution_id="graph-resolution-1",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            subject_node_id=self.subject.node_id,
            subject_decision_id=self.subject_decision_id,
            materialization_resolution_id=self.materialization.resolution_id,
            effect_ids=(self.effect.effect_id,),
        )

    def _materialize_and_effect(\n        self,\n        future,\n        *,\n        suffix: str,\n        direction: RiskDirection = RiskDirection.INCREASED,\n    ):
        run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        context = RunContext.for_lab(
            run_id,
            engagement_id=f"graph-{suffix}",
            client_id="client-1",
        )
        evidence_id = self.state.add_evidence(
            run_id,
            "web",
            "future-materialization-observation",
            "lab-fixture",
            f"isolated {suffix}".encode(),
            metadata={
                "client_id": "client-1",
                "engagement_id": f"graph-{suffix}",
                "mode": "lab_autonomous",
                "is_lab": "true",
            },
        )
        materialization = FutureMaterializationResolution(
            resolution_id=f"materialization-{suffix}",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            run_id=run_id,
            outcome=MaterializationOutcome.CONFIRMED,
            equivalence=EnvironmentEquivalence.PARTIAL,
            evidence_ids=(evidence_id,),
            capability_ids=("web",),
        )
        materialized = apply_future_materialization_resolution(
            future, materialization, context, self.state
        )
        effect = FutureSecurityEffect(
            effect_id=f"effect-{suffix}",
            resolution_id=materialization.resolution_id,
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            capability_id="web",
            kind=SecurityEffectKind.ATTACK_SURFACE_ADDED,
            risk_direction=direction,
            evidence_ids=(evidence_id,),
        )
        return (
            apply_future_security_effects(
                materialized, materialization, (effect,)
            ),
            materialization,
            effect,
        )

    def test_verified_subject_and_effects_resolve_without_attack_path_mutation(self):
        resolved = apply_future_graph_resolution(
            self.reviewed,
            self.graph,
            self.materialization,
            self.state,
        )

        links = [
            relationship
            for relationship in resolved.relationships
            if relationship.relation == "verified_effects_on_subject"
        ]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].source_id, self.change_node.node_id)
        self.assertEqual(links[0].target_id, self.subject.node_id)
        self.assertEqual(resolved.attack_paths, self.reviewed.attack_paths)
        self.assertEqual(dict(resolved.metadata)["future_graph_resolution_count"], "1")
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        graph_effect_ids = {
            fact.value
            for fact in resolved.facts
            if fact.predicate == "future_graph.effect_id"
        }
        self.assertEqual(graph_effect_ids, {self.effect.effect_id})
        report = review_future_subjects(
            resolved,
            self.state,
            AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
        )
        self.assertTrue(report.graph_resolution_complete)
        self.assertEqual(report.unresolved_graph_count, 0)
        self.assertEqual(report.items[0].graph_resolution_status, "verified")
        self.assertEqual(
            report.items[0].graph_resolution_id,
            self.graph.graph_resolution_id,
        )
        self.assertEqual(
            report.items[0].resolved_effect_ids,
            (self.effect.effect_id,),
        )
        self.assertEqual(
            report.items[0].next_action,
            "await_attack_path_analysis",
        )
        self.assertEqual(report.security_verdict, "not_evaluated")

    def test_graph_resolution_requires_explicit_verified_subject_decision(self):
        with self.assertRaisesRegex(ValueError, "explicit verified subject"):
            apply_future_graph_resolution(
                self.effected,
                self.graph,
                self.materialization,
                self.state,
            )

    def test_real_ambiguous_and_missing_bindings_cannot_graph_resolve(self):
        other = TwinNode(
            "api-2",
            TwinNodeKind.API,
            "Second API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        ambiguous_future = self.future.next_snapshot(
            nodes=self.future.nodes + (other,)
        )
        ambiguous_bound, ambiguous_bindings = bind_future_change_candidates(
            ambiguous_future, self.changeset
        )
        self.assertEqual(ambiguous_bindings[0].status.value, "ambiguous")
        ambiguous_effected, ambiguous_materialization, ambiguous_effect = (
            self._materialize_and_effect(ambiguous_bound, suffix="ambiguous")
        )

        missing_bound, missing_bindings = bind_future_change_candidates(
            self.future, self.changeset, candidates={}
        )
        self.assertEqual(missing_bindings[0].status.value, "no_candidate")
        missing_effected, missing_materialization, missing_effect = (
            self._materialize_and_effect(missing_bound, suffix="missing")
        )

        cases = (
            (
                ambiguous_effected,
                ambiguous_materialization,
                ambiguous_effect.effect_id,
            ),
            (
                missing_effected,
                missing_materialization,
                missing_effect.effect_id,
            ),
        )
        for future, materialization, effect_id in cases:
            with self.subTest(effect_id=effect_id):
                graph = dataclasses.replace(
                    self.graph,
                    graph_resolution_id=f"graph-{effect_id}",
                    materialization_resolution_id=materialization.resolution_id,
                    effect_ids=(effect_id,),
                )
                with self.assertRaises(ValueError):
                    apply_future_graph_resolution(
                        future, graph, materialization, self.state
                    )

    def test_forged_subject_or_cross_tenant_resolution_fails_closed(self):
        with self.assertRaises((KeyError, ValueError)):
            apply_future_graph_resolution(
                self.reviewed,
                dataclasses.replace(self.graph, subject_node_id="api-forged"),
                self.materialization,
                self.state,
            )
        with self.assertRaises(ValueError):
            apply_future_graph_resolution(
                self.reviewed,
                dataclasses.replace(self.graph, client_id="client-2"),
                self.materialization,
                self.state,
            )

    def test_missing_or_foreign_effect_state_fails_closed(self):
        missing_fact_id = _effect_fact_id(
            self.effect.effect_id, "future_effect.kind"
        )
        missing = dataclasses.replace(
            self.reviewed,
            facts=tuple(
                fact
                for fact in self.reviewed.facts
                if fact.fact_id != missing_fact_id
            ),
        )
        with self.assertRaisesRegex(ValueError, "missing future effect"):
            apply_future_graph_resolution(
                missing, self.graph, self.materialization, self.state
            )

        resolution_fact_id = _effect_fact_id(
            self.effect.effect_id, "future_effect.resolution_id"
        )
        foreign = dataclasses.replace(
            self.reviewed,
            facts=tuple(
                dataclasses.replace(fact, value="other-materialization")
                if fact.fact_id == resolution_fact_id
                else fact
                for fact in self.reviewed.facts
            ),
        )
        with self.assertRaisesRegex(ValueError, "another materialization"):
            apply_future_graph_resolution(
                foreign, self.graph, self.materialization, self.state
            )

    def test_deleted_materialization_evidence_fails_closed(self):
        with self.state.connect() as con:
            con.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (self.materialization_evidence_id,),
            )

        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            apply_future_graph_resolution(
                self.reviewed,
                self.graph,
                self.materialization,
                self.state,
            )

    def test_review_revalidates_graph_evidence_after_resolution(self):
        resolved = apply_future_graph_resolution(
            self.reviewed, self.graph, self.materialization, self.state
        )
        with self.state.connect() as con:
            con.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (self.materialization_evidence_id,),
            )

        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            review_future_subjects(
                resolved,
                self.state,
                AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
            )

    def test_review_rejects_effect_semantics_tampering_after_graph_resolution(self):
        resolved = apply_future_graph_resolution(
            self.reviewed, self.graph, self.materialization, self.state
        )
        risk_fact_id = _effect_fact_id(
            self.effect.effect_id, "future_effect.risk_direction"
        )
        forged = dataclasses.replace(
            resolved,
            facts=tuple(
                dataclasses.replace(
                    fact, value=RiskDirection.DECREASED.value
                )
                if fact.fact_id == risk_fact_id
                else fact
                for fact in resolved.facts
            ),
        )

        with self.assertRaisesRegex(ValueError, "effect semantics digest"):
            review_future_subjects(
                forged,
                self.state,
                AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
            )

    def test_exact_replay_is_idempotent(self):
        once = apply_future_graph_resolution(
            self.reviewed, self.graph, self.materialization, self.state
        )
        twice = apply_future_graph_resolution(
            once, self.graph, self.materialization, self.state
        )
        self.assertIs(twice, once)

    def test_same_graph_id_with_changed_semantics_fails_closed(self):
        second_effect = dataclasses.replace(
            self.effect,
            effect_id="effect-graph-2",
            kind=SecurityEffectKind.CONTROL_WEAKENED,
        )
        with_two_effects = apply_future_security_effects(
            self.reviewed,
            self.materialization,
            (second_effect,),
        )
        once = apply_future_graph_resolution(
            with_two_effects, self.graph, self.materialization, self.state
        )
        conflicting = dataclasses.replace(
            self.graph,
            effect_ids=(second_effect.effect_id,),
        )
        with self.assertRaises(ValueError):
            apply_future_graph_resolution(
                once, conflicting, self.materialization, self.state
            )

    def test_duplicate_effect_ids_are_rejected_before_state_mutation(self):
        duplicate = dataclasses.replace(
            self.graph,
            effect_ids=(self.effect.effect_id, self.effect.effect_id),
        )
        with self.assertRaisesRegex(ValueError, "effect_ids must be unique"):
            apply_future_graph_resolution(
                self.reviewed, duplicate, self.materialization, self.state
            )


if __name__ == "__main__":
    unittest.main()
