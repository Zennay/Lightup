"""Exercise staged ST3 against actual ST2 binding and ST3 effect producers.

Run after composing the pinned predecessor commits in an ephemeral CI checkout:
PYTHONPATH=src:tests python -m unittest discover -s tests/integration -v
No hand-built candidate graph substitutes for bind_future_change_candidates.
"""
import dataclasses
import hashlib
import unittest

import test_future_subject_resolution as subject_tests
from lightup.ai.orchestration import RunContext
from lightup.future_binding import bind_future_change_candidates
from lightup.future_effects import (
    FutureSecurityEffect, RiskDirection, SecurityEffectKind,
    apply_future_security_effects,
)
from lightup.future_materialization import (
    EnvironmentEquivalence, FutureMaterializationResolution,
    MaterializationOutcome, apply_future_materialization_resolution,
)
from lightup.future_graph_resolution import (
    FutureGraphResolution, apply_future_graph_resolution,
)
from lightup.future_attack_path_analysis import analyze_future_attack_path_impact
from lightup.future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    build_future_attack_path_graph_diff_preview,
)
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition import propose_future_attack_path_transitions
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    future_attack_path_transition_evidence_contract,
    verify_future_attack_path_transition,
)
from lightup.domain import AccessContext, Role
from lightup.future_subject_resolution import apply_future_subject_resolution
from lightup.future_subject_review import review_future_subjects
from lightup.github_changes import github_pull_request_changeset
from lightup.changes import derive_future_twin
from lightup.twin import AttackPath, AttackStep, FactProvenance, TwinNode, TwinNodeKind


class RealBindingSubjectResolutionTest(subject_tests.FutureSubjectResolutionTest):
    """Replay the resolver contract using the real ST2 producer."""

    def setUp(self):
        super().setUp()
        actual, bindings = bind_future_change_candidates(self.future, self.changeset)
        self.assertEqual(len(bindings), 1)
        self.assertEqual(actual, self.bound)
        self.bound = actual

    def _review(self, future, decision_id):
        metadata = dict(self.state.get_evidence(self.evidence_id).metadata)
        metadata.update(
            decision_id=decision_id, future_twin_version=str(future.version)
        )
        evidence_id = self.state.add_evidence(
            self.run_id, "future-subject-resolution", "operator-review",
            "operator", b"review of the exact composed future",
            metadata=metadata,
        )
        return dataclasses.replace(
            self.resolution, decision_id=decision_id, evidence_ids=(evidence_id,)
        )

    def _materialize_bundle(
        self,
        future,
        *,
        suffix: str = "integration",
        direction: RiskDirection = RiskDirection.INCREASED,
    ):
        engagement_id = (
            "integration-lab"
            if suffix == "integration"
            else f"integration-lab-{suffix}"
        )
        run_id = self.state.create_run("127.0.0.1", activation_mode="lab_autonomous")
        context = RunContext.for_lab(
            run_id, engagement_id=engagement_id, client_id="client-1"
        )
        evidence_id = self.state.add_evidence(
            run_id, "web", "future-materialization-observation", "lab-fixture",
            f"isolated synthetic route observation {suffix}; no network execution".encode(),
            metadata={
                "client_id": "client-1", "engagement_id": engagement_id,
                "mode": "lab_autonomous", "is_lab": "true",
            },
        )
        resolution = FutureMaterializationResolution(
            resolution_id=f"materialization-{suffix}", client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id, run_id=run_id,
            outcome=MaterializationOutcome.CONFIRMED,
            equivalence=EnvironmentEquivalence.PARTIAL,
            evidence_ids=(evidence_id,), capability_ids=("web",),
            limitations=("synthetic fixture; production equivalence not claimed",),
        )
        materialized = apply_future_materialization_resolution(
            future, resolution, context, self.state
        )
        effect = FutureSecurityEffect(
            effect_id=f"effect-{suffix}", resolution_id=resolution.resolution_id,
            client_id="client-1", changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id, capability_id="web",
            kind=SecurityEffectKind.ATTACK_SURFACE_ADDED,
            risk_direction=direction, evidence_ids=(evidence_id,),
        )
        effected = apply_future_security_effects(
            materialized, resolution, (effect,)
        )
        return effected, resolution, effect

    def _materialize(self, future):
        return self._materialize_bundle(future)[0]

    def _graph_diff_preview_from_real_pipeline(
        self,
        *,
        classification: AttackPathTransitionClassification,
        direction: RiskDirection,
        suffix: str,
        with_existing_path: bool,
    ):
        current = self.current
        if with_existing_path:
            path_id = f"path-integration-{suffix}"
            path = AttackPath(
                path_id=path_id,
                title=f"Existing integration path {suffix}",
                steps=(
                    AttackStep(
                        source_id=self.subject.node_id,
                        target_id=self.subject.node_id,
                        relation="existing_self_reference",
                    ),
                ),
                evidence_refs=(f"evidence:{path_id}",),
            )
            current = current.next_snapshot(
                attack_paths=current.attack_paths + (path,)
            )

        before_current = dataclasses.asdict(current)
        future = derive_future_twin(current, self.changeset)
        bound, bindings = bind_future_change_candidates(future, self.changeset)
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].status.value, "single_candidate")

        effected, materialization, effect = self._materialize_bundle(
            bound,
            suffix=f"preview-{suffix}",
            direction=direction,
        )
        candidate = next(
            relationship
            for relationship in bound.relationships
            if relationship.relation == "candidate_affects"
            and relationship.source_id == self.change_node.node_id
        )
        candidate_digest = hashlib.sha256(
            "\x1f".join(sorted(candidate.evidence_refs)).encode("utf-8")
        ).hexdigest()
        decision_id = f"decision-preview-{suffix}"
        subject_evidence_id = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            f"integration subject review {suffix}".encode("utf-8"),
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": decision_id,
                "client_id": "client-1",
                "future_twin_id": effected.twin_id,
                "future_twin_version": str(effected.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": self.change_node.node_id,
                "subject_node_id": self.subject.node_id,
                "candidate_evidence_sha256": candidate_digest,
                "resolution_basis": self.resolution.basis.value,
                "rationale_sha256": hashlib.sha256(
                    self.rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        subject_resolution = dataclasses.replace(
            self.resolution,
            decision_id=decision_id,
            evidence_ids=(subject_evidence_id,),
        )
        reviewed = apply_future_subject_resolution(
            effected, subject_resolution, self.state
        )
        graph = FutureGraphResolution(
            graph_resolution_id=f"graph-preview-{suffix}",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            subject_node_id=self.subject.node_id,
            subject_decision_id=decision_id,
            materialization_resolution_id=materialization.resolution_id,
            effect_ids=(effect.effect_id,),
        )
        resolved = apply_future_graph_resolution(
            reviewed, graph, materialization, self.state
        )
        before_future_paths = resolved.attack_paths
        impact = analyze_future_attack_path_impact(
            resolved,
            self.state,
            AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
            current=current,
        )
        proposal = propose_future_attack_path_transitions(impact)

        transition_run_id = self.state.create_run(
            "127.0.0.1", activation_mode="lab_autonomous"
        )
        transition_context = RunContext.for_lab(
            transition_run_id,
            engagement_id=f"integration-transition-{suffix}",
            client_id="client-1",
        )
        transition_metadata = future_attack_path_transition_evidence_contract(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            context=transition_context,
        )
        transition_evidence_id = self.state.add_evidence(
            transition_run_id,
            "web",
            "future-transition-verification",
            "integration-lab-fixture",
            f"integration transition proof {suffix}".encode("utf-8"),
            metadata=transition_metadata,
        )
        transition_resolution = verify_future_attack_path_transition(
            proposal,
            change_node_id=proposal.items[0].change_node_id,
            classification=classification,
            run_id=transition_run_id,
            evidence_ids=(transition_evidence_id,),
            capability_ids=("web",),
            context=transition_context,
            state=self.state,
        )
        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (transition_resolution,),
            (transition_context,),
            self.state,
        )

        self.assertEqual(dataclasses.asdict(current), before_current)
        self.assertEqual(resolved.attack_paths, before_future_paths)
        return (
            current,
            resolved,
            proposal,
            preview,
            transition_context,
            transition_resolution,
        )

    def test_materialized_effects_then_subject_review_preserve_all_evidence(self):
        effected = self._materialize(self.bound)
        review = self._review(effected, "decision-after-effects")
        resolved = apply_future_subject_resolution(effected, review, self.state)
        self.assertIs(
            apply_future_subject_resolution(resolved, review, self.state), resolved
        )
        self.assertTrue(set(effected.facts).issubset(set(resolved.facts)))
        self.assertEqual(resolved.attack_paths, self.current.attack_paths)
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        self.assertEqual(dict(resolved.metadata)["future_security_effect_count"], "1")
        self.assertEqual(dict(resolved.metadata)["future_subject_resolution_count"], "1")
        self.assertTrue(all(
            fact.provenance is FactProvenance.INFERRED
            for fact in resolved.facts if fact.predicate.startswith("change.")
        ))

    def test_real_pipeline_resolves_verified_effects_onto_reviewed_subject(self):
        effected, materialization, effect = self._materialize_bundle(self.bound)
        reviewed = apply_future_subject_resolution(
            effected,
            self._review(effected, "graph-integration-review"),
            self.state,
        )
        graph = FutureGraphResolution(
            graph_resolution_id="graph-integration",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            subject_node_id=self.subject.node_id,
            subject_decision_id="graph-integration-review",
            materialization_resolution_id=materialization.resolution_id,
            effect_ids=(effect.effect_id,),
        )

        resolved = apply_future_graph_resolution(
            reviewed, graph, materialization, self.state
        )

        self.assertEqual(resolved.attack_paths, self.current.attack_paths)
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        self.assertEqual(dict(resolved.metadata)["future_graph_resolution_count"], "1")
        self.assertEqual(
            [
                relationship.target_id
                for relationship in resolved.relationships
                if relationship.relation == "verified_effects_on_subject"
            ],
            [self.subject.node_id],
        )
        self.assertIs(
            apply_future_graph_resolution(
                resolved, graph, materialization, self.state
            ),
            resolved,
        )
        report = review_future_subjects(
            resolved,
            self.state,
            AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
        )
        self.assertTrue(report.graph_resolution_complete)
        self.assertEqual(report.items[0].graph_resolution_status, "verified")
        self.assertEqual(report.items[0].graph_resolution_id, "graph-integration")
        self.assertEqual(
            report.items[0].resolved_effect_ids,
            ("effect-integration",),
        )
        self.assertEqual(
            report.items[0].next_action,
            "await_attack_path_analysis",
        )
        self.assertEqual(report.security_verdict, "not_evaluated")

        impact = analyze_future_attack_path_impact(
            resolved,
            self.state,
            AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
            current=self.current,
        )
        self.assertTrue(impact.analysis_complete)
        self.assertEqual(impact.security_verdict, "not_evaluated")
        self.assertEqual(impact.future_semantics, "unresolved")
        self.assertEqual(len(impact.items), 1)
        self.assertEqual(impact.items[0].impact, "potential_regression")
        self.assertEqual(
            impact.items[0].materialization_resolution_id,
            materialization.resolution_id,
        )
        self.assertEqual(
            impact.items[0].subject_decision_id,
            "graph-integration-review",
        )
        self.assertEqual(
            impact.items[0].effect_ids,
            ("effect-integration",),
        )
        self.assertEqual(impact.items[0].current_attack_path_ids, ())
        self.assertEqual(resolved.attack_paths, self.current.attack_paths)

    def test_real_pipeline_reaches_graph_diff_preview_for_all_st4_outcomes(self):
        cases = (
            (
                AttackPathTransitionClassification.INTRODUCED,
                RiskDirection.INCREASED,
                False,
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
                False,
                "introduced",
            ),
            (
                AttackPathTransitionClassification.WORSENED,
                RiskDirection.INCREASED,
                True,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
                False,
                "worsened",
            ),
            (
                AttackPathTransitionClassification.IMPROVED,
                RiskDirection.DECREASED,
                True,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
                False,
                "improved",
            ),
            (
                AttackPathTransitionClassification.REMOVED,
                RiskDirection.DECREASED,
                True,
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
                False,
                "removed",
            ),
            (
                AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
                RiskDirection.INCREASED,
                False,
                AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
                True,
                "insufficient",
            ),
        )
        for (
            classification,
            direction,
            with_existing_path,
            expected_action,
            expected_insufficient,
            suffix,
        ) in cases:
            with self.subTest(classification=classification.value):
                (
                    current,
                    resolved,
                    proposal,
                    preview,
                    transition_context,
                    transition_resolution,
                ) = self._graph_diff_preview_from_real_pipeline(
                        classification=classification,
                        direction=direction,
                        suffix=suffix,
                        with_existing_path=with_existing_path,
                    )
                before_current = dataclasses.asdict(current)
                before_future_paths = resolved.attack_paths
                report = build_future_attack_path_security_delta_report(
                    preview,
                    proposal,
                    (transition_resolution,),
                    (transition_context,),
                    self.state,
                )
                self.assertTrue(preview.preview_complete)
                self.assertEqual(
                    preview.contains_insufficient_evidence,
                    expected_insufficient,
                )
                self.assertEqual(preview.items[0].action, expected_action)
                self.assertEqual(
                    preview.items[0].current_attack_path_ids,
                    proposal.items[0].current_attack_path_ids,
                )
                self.assertEqual(
                    preview.items[0].current_attack_path_ids,
                    tuple(path.path_id for path in current.attack_paths),
                )
                self.assertFalse(preview.attack_path_mutation_allowed)
                self.assertEqual(preview.future_semantics, "unresolved")
                self.assertEqual(preview.security_verdict, "not_evaluated")
                self.assertTrue(report.report_complete)
                self.assertEqual(report.preview_sha256, preview.preview_sha256)
                self.assertEqual(report.items[0].classification, classification)
                self.assertEqual(report.items[0].action, expected_action)
                self.assertEqual(
                    report.items[0].evidence_ids,
                    transition_resolution.evidence_ids,
                )
                self.assertEqual(
                    report.items[0].capability_ids,
                    transition_resolution.capability_ids,
                )
                self.assertEqual(
                    report.contains_insufficient_evidence,
                    expected_insufficient,
                )
                self.assertFalse(report.attack_path_mutation_allowed)
                self.assertEqual(report.future_semantics, "unresolved")
                self.assertEqual(report.security_verdict, "not_evaluated")
                self.assertEqual(dataclasses.asdict(current), before_current)
                self.assertEqual(resolved.attack_paths, before_future_paths)

    def test_snapshot_bound_review_cannot_be_reused_after_materialization(self):
        effected = self._materialize(self.bound)
        with self.assertRaisesRegex(ValueError, "future_twin_version"):
            apply_future_subject_resolution(effected, self.resolution, self.state)

    def test_real_ambiguous_binding_never_promotes_a_subject(self):
        other = TwinNode(
            "api-2", TwinNodeKind.API, "Second API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        future = self.future.next_snapshot(nodes=self.future.nodes + (other,))
        bound, bindings = bind_future_change_candidates(future, self.changeset)
        self.assertEqual(bindings[0].status.value, "ambiguous")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            apply_future_subject_resolution(bound, self._review(bound, "ambiguous"), self.state)

    def test_real_missing_binding_never_promotes_a_subject(self):
        bound, bindings = bind_future_change_candidates(
            self.future, self.changeset, candidates={}
        )
        self.assertEqual(bindings[0].status.value, "no_candidate")
        with self.assertRaisesRegex(ValueError, "existing inferred"):
            apply_future_subject_resolution(bound, self._review(bound, "missing"), self.state)

    def test_explicit_real_binding_requires_and_accepts_exact_review(self):
        signal_id = self.changeset.semantic_signals[0].signal_id
        bound, _ = bind_future_change_candidates(
            self.future, self.changeset,
            candidates={signal_id: (self.subject.node_id,)},
        )
        review = self._review(bound, "explicit-review")
        resolved = apply_future_subject_resolution(bound, review, self.state)
        self.assertEqual(dict(resolved.metadata)["future_subject_resolution_count"], "1")
        self.assertEqual(resolved.attack_paths, self.current.attack_paths)

    def test_review_explains_real_missing_and_ambiguous_candidates(self):
        context = AccessContext("reader", Role.CLIENT_MEMBER, "client-1")
        other = TwinNode(
            "api-2", TwinNodeKind.API, "Second API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        future = self.future.next_snapshot(nodes=self.future.nodes + (other,))
        cases = (
            ({}, "no_candidate", "supply_candidate_mapping"),
            (None, "ambiguous", "disambiguate_candidate_mapping"),
        )
        for candidates, status, action in cases:
            with self.subTest(status=status):
                bound, _ = bind_future_change_candidates(
                    future, self.changeset, candidates=candidates
                )
                report = review_future_subjects(bound, self.state, context)
                self.assertEqual(report.items[0].binding_status, status)
                self.assertEqual(report.items[0].next_action, action)
                self.assertEqual(report.unresolved_change_count, 1)
                self.assertFalse(report.subject_review_complete)
                self.assertEqual(report.security_verdict, "not_evaluated")

    def test_review_of_materialized_and_verified_subject_is_still_not_a_verdict(self):
        effected = self._materialize(self.bound)
        reviewed = apply_future_subject_resolution(
            effected, self._review(effected, "report-reviewed"), self.state
        )
        report = review_future_subjects(
            reviewed, self.state,
            AccessContext("operator", Role.OPERATOR), client_id="client-1",
        )
        self.assertTrue(report.subject_review_complete)
        self.assertEqual(report.items[0].decision_id, "report-reviewed")
        self.assertEqual(report.items[0].next_action, "await_effect_graph_resolution")
        self.assertEqual(report.future_semantics, "unresolved")
        self.assertEqual(report.security_verdict, "not_evaluated")
        self.assertEqual(reviewed.attack_paths, self.current.attack_paths)

    def test_no_semantic_changes_do_not_produce_vacuous_approval(self):
        changeset = github_pull_request_changeset(
            client_id="client-1", repository="Zennay/Lightup", pr_number=141,
            base_sha="c" * 40, head_sha="d" * 40,
            files=({
                "filename": "README.md", "status": "modified",
                "additions": 1, "deletions": 0,
                "patch": "@@ -1,0 +1 @@\\n+Documentation update",
            },),
        )
        future = derive_future_twin(self.current, changeset)
        bound, bindings = bind_future_change_candidates(future, changeset)
        self.assertEqual(bindings, ())
        report = review_future_subjects(
            bound, self.state,
            AccessContext("reader", Role.CLIENT_MEMBER, "client-1"),
        )
        self.assertEqual(report.items, ())
        self.assertFalse(report.subject_review_complete)
        self.assertEqual(report.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
