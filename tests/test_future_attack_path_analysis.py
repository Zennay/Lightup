from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest
from unittest.mock import patch

import test_future_graph_resolution as graph_tests
from lightup.changes import derive_future_twin
from lightup.future_binding import bind_future_change_candidates
from lightup.domain import AccessContext, Role, TenantIsolationError
from lightup.future_attack_path_analysis import (
    analyze_future_attack_path_impact,
    future_attack_path_impact_report_from_dict,
    validate_future_attack_path_impact_report,
)
from lightup.future_effects import (
    FutureSecurityEffect,
    RiskDirection,
    SecurityEffectKind,
    apply_future_security_effects,
)
from lightup.future_graph_resolution import (
    FutureGraphResolution,
    apply_future_graph_resolution,
)
from lightup.future_subject_resolution import apply_future_subject_resolution
from lightup.twin import AttackPath, AttackStep


class FutureAttackPathImpactAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.f = graph_tests.FutureGraphResolutionTest(
            "test_verified_subject_and_effects_resolve_without_attack_path_mutation"
        )
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.client = AccessContext("client-reader", Role.CLIENT_MEMBER, "client-1")

    def _resolved_with(
        self,
        effects: tuple[FutureSecurityEffect, ...],
        *,
        graph_id: str = "graph-impact",
    ):
        future = self.f.reviewed
        new_effects = tuple(
            effect
            for effect in effects
            if effect.effect_id != self.f.effect.effect_id
        )
        if new_effects:
            future = apply_future_security_effects(
                future,
                self.f.materialization,
                new_effects,
            )

        graph = FutureGraphResolution(
            graph_resolution_id=graph_id,
            client_id="client-1",
            changeset_id=self.f.changeset.changeset_id,
            change_node_id=self.f.change_node.node_id,
            subject_node_id=self.f.subject.node_id,
            subject_decision_id=self.f.subject_decision_id,
            materialization_resolution_id=self.f.materialization.resolution_id,
            effect_ids=tuple(effect.effect_id for effect in effects),
        )
        return apply_future_graph_resolution(
            future,
            graph,
            self.f.materialization,
            self.f.state,
        )

    def _resolved_from_current(self, current, *, graph_id: str):
        future = derive_future_twin(current, self.f.changeset)
        bound, bindings = bind_future_change_candidates(
            future, self.f.changeset
        )
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].status.value, "single_candidate")
        effected, materialization, effect = self.f._materialize_and_effect(
            bound, suffix=graph_id
        )
        candidate = next(
            relationship
            for relationship in bound.relationships
            if relationship.relation == "candidate_affects"
            and relationship.source_id == self.f.change_node.node_id
        )
        candidate_digest = hashlib.sha256(
            "\x1f".join(sorted(candidate.evidence_refs)).encode("utf-8")
        ).hexdigest()
        decision_id = f"decision-{graph_id}"
        evidence_id = self.f.state.add_evidence(
            self.f.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            f"review for {graph_id}".encode("utf-8"),
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": decision_id,
                "client_id": "client-1",
                "future_twin_id": effected.twin_id,
                "future_twin_version": str(effected.version),
                "changeset_id": self.f.changeset.changeset_id,
                "change_node_id": self.f.change_node.node_id,
                "subject_node_id": self.f.subject.node_id,
                "candidate_evidence_sha256": candidate_digest,
                "resolution_basis": self.f.resolution.basis.value,
                "rationale_sha256": hashlib.sha256(
                    self.f.rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        subject_resolution = dataclasses.replace(
            self.f.resolution,
            decision_id=decision_id,
            evidence_ids=(evidence_id,),
        )
        reviewed = apply_future_subject_resolution(
            effected, subject_resolution, self.f.state
        )
        graph = FutureGraphResolution(
            graph_resolution_id=graph_id,
            client_id="client-1",
            changeset_id=self.f.changeset.changeset_id,
            change_node_id=self.f.change_node.node_id,
            subject_node_id=self.f.subject.node_id,
            subject_decision_id=decision_id,
            materialization_resolution_id=materialization.resolution_id,
            effect_ids=(effect.effect_id,),
        )
        return apply_future_graph_resolution(
            reviewed,
            graph,
            materialization,
            self.f.state,
        )

    def _effect(
        self,
        effect_id: str,
        direction: RiskDirection,
        *,
        kind: SecurityEffectKind = SecurityEffectKind.CONTROL_STRENGTHENED,
    ) -> FutureSecurityEffect:
        return FutureSecurityEffect(
            effect_id=effect_id,
            resolution_id=self.f.materialization.resolution_id,
            client_id="client-1",
            changeset_id=self.f.changeset.changeset_id,
            change_node_id=self.f.change_node.node_id,
            capability_id="web",
            kind=kind,
            risk_direction=direction,
            evidence_ids=(self.f.materialization_evidence_id,),
        )

    def test_increased_effect_reports_potential_regression_and_existing_path(self):
        path = AttackPath(
            path_id="path-existing-1",
            title="Existing path touching reviewed API",
            steps=(
                AttackStep(
                    source_id=self.f.subject.node_id,
                    target_id=self.f.subject.node_id,
                    relation="existing_self_reference",
                ),
            ),
            evidence_refs=("evidence:existing-path",),
        )
        current = self.f.current.next_snapshot(
            attack_paths=self.f.current.attack_paths + (path,)
        )
        resolved = self._resolved_from_current(
            current,
            graph_id="graph-impact-increased",
        )
        before = dataclasses.asdict(resolved)
        report = analyze_future_attack_path_impact(
            resolved, self.f.state, self.client, current=current
        )

        self.assertTrue(report.analysis_complete)
        self.assertEqual(report.security_verdict, "not_evaluated")
        self.assertEqual(report.future_semantics, "unresolved")
        self.assertEqual(len(report.items), 1)
        item = report.items[0]
        self.assertEqual(item.impact, "potential_regression")
        self.assertEqual(item.risk_directions, ("increased",))
        self.assertEqual(
            item.subject_decision_id,
            "decision-graph-impact-increased",
        )
        self.assertEqual(
            item.materialization_resolution_id,
            "materialization-graph-impact-increased",
        )
        self.assertEqual(item.current_attack_path_ids, ("path-existing-1",))
        self.assertEqual(report.current_twin_id, current.twin_id)
        self.assertEqual(report.current_twin_version, current.version)
        self.assertEqual(dataclasses.asdict(resolved), before)
        exported = json.loads(json.dumps(report.as_dict()))
        exported["items"][0]["impact"] = "mutated"
        self.assertEqual(item.impact, "potential_regression")

    def test_decreased_effect_reports_potential_improvement_without_safety_claim(self):
        decreased = self._effect(
            "effect-impact-decreased",
            RiskDirection.DECREASED,
        )
        resolved = self._resolved_with(
            (decreased,),
            graph_id="graph-impact-decreased",
        )
        report = analyze_future_attack_path_impact(
            resolved, self.f.state, self.client, current=self.f.current
        )

        self.assertEqual(report.items[0].impact, "potential_improvement")
        self.assertEqual(report.items[0].current_attack_path_ids, ())
        self.assertEqual(report.security_verdict, "not_evaluated")

    def test_mixed_and_unchanged_classification(self):
        decreased = self._effect(
            "effect-impact-mixed-decreased",
            RiskDirection.DECREASED,
        )
        mixed = self._resolved_with(
            (self.f.effect, decreased),
            graph_id="graph-impact-mixed",
        )
        mixed_report = analyze_future_attack_path_impact(
            mixed, self.f.state, self.client, current=self.f.current
        )
        self.assertEqual(mixed_report.items[0].impact, "mixed")

        unchanged = self._effect(
            "effect-impact-unchanged",
            RiskDirection.UNCHANGED,
            kind=SecurityEffectKind.CONTROL_STRENGTHENED,
        )
        unchanged_resolved = self._resolved_with(
            (unchanged,),
            graph_id="graph-impact-unchanged",
        )
        unchanged_report = analyze_future_attack_path_impact(
            unchanged_resolved, self.f.state, self.client, current=self.f.current
        )
        self.assertEqual(unchanged_report.items[0].impact, "unchanged")

    def test_materialization_identity_mismatch_is_rejected(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-materialization-mismatch",
        )
        materialization_fact = next(
            fact
            for fact in resolved.facts
            if fact.subject_id == self.f.change_node.node_id
            and fact.predicate == "future_graph.materialization_resolution_id"
        )
        forged = dataclasses.replace(
            resolved,
            facts=tuple(
                dataclasses.replace(fact, value="materialization-forged")
                if fact.fact_id == materialization_fact.fact_id
                else fact
                for fact in resolved.facts
            ),
        )

        with self.assertRaises(ValueError):
            analyze_future_attack_path_impact(
                forged,
                self.f.state,
                self.client,
                current=self.f.current,
            )

    def test_verified_subject_must_match_current_baseline_identity(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-subject-drift",
        )
        forged_subject = dataclasses.replace(
            self.f.subject,
            label="Forged current subject identity",
        )
        forged = resolved.next_snapshot(
            nodes=tuple(
                forged_subject
                if node.node_id == self.f.subject.node_id
                else node
                for node in resolved.nodes
            )
        )

        with self.assertRaisesRegex(ValueError, "subject drifted"):
            analyze_future_attack_path_impact(
                forged,
                self.f.state,
                self.client,
                current=self.f.current,
            )

        current_missing = dataclasses.replace(
            self.f.current,
            nodes=tuple(
                node
                for node in self.f.current.nodes
                if node.node_id != self.f.subject.node_id
            ),
        )
        missing_metadata = dict(resolved.metadata)
        missing_metadata.update(
            {
                "future_base_twin_id": current_missing.twin_id,
                "future_base_twin_version": str(current_missing.version),
                "future_base_twin_sha256": current_missing.stable_digest(),
            }
        )
        forged_missing = dataclasses.replace(
            resolved,
            metadata=tuple(sorted(missing_metadata.items())),
        )
        with self.assertRaisesRegex(ValueError, "absent from current baseline"):
            analyze_future_attack_path_impact(
                forged_missing,
                self.f.state,
                self.client,
                current=current_missing,
            )

    def test_future_attack_path_drift_from_current_baseline_is_rejected(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-path-drift",
        )
        forged_path = AttackPath(
            path_id="path-forged-future",
            title="Unexpected future-only path",
            steps=(
                AttackStep(
                    source_id=self.f.subject.node_id,
                    target_id=self.f.change_node.node_id,
                    relation="unexpected_future_transition",
                ),
            ),
        )
        forged = resolved.next_snapshot(
            attack_paths=resolved.attack_paths + (forged_path,)
        )

        with self.assertRaisesRegex(ValueError, "unchanged from current baseline"):
            analyze_future_attack_path_impact(
                forged,
                self.f.state,
                self.client,
                current=self.f.current,
            )

    def test_current_baseline_must_be_current_and_same_tenant(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-current-baseline",
        )
        with self.assertRaisesRegex(ValueError, "current Security Twin baseline"):
            analyze_future_attack_path_impact(
                resolved,
                self.f.state,
                self.client,
                current=self.f.future,
            )
        other_current = dataclasses.replace(
            self.f.current,
            twin_id="other-current",
            client_id="client-2",
        )
        with patch.object(self.f.state, "get_evidence") as lookup:
            with self.assertRaisesRegex(
                TenantIsolationError, "cannot cross tenants"
            ):
                analyze_future_attack_path_impact(
                    resolved,
                    self.f.state,
                    self.client,
                    current=other_current,
                )
            lookup.assert_not_called()

    def test_same_tenant_but_unrelated_current_baseline_is_rejected(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-baseline-lineage",
        )
        wrong_id = dataclasses.replace(
            self.f.current,
            twin_id="unrelated-current-twin",
        )
        wrong_version = dataclasses.replace(
            self.f.current,
            version=self.f.current.version + 1,
        )

        for current in (wrong_id, wrong_version):
            with self.subTest(
                twin_id=current.twin_id,
                version=current.version,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "current baseline identity does not match future lineage",
                ):
                    analyze_future_attack_path_impact(
                        resolved,
                        self.f.state,
                        self.client,
                        current=current,
                    )

    def test_unresolved_graph_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "complete verified graph"):
            analyze_future_attack_path_impact(
                self.f.reviewed,
                self.f.state,
                self.client,
                current=self.f.current,
            )

    def test_analysis_digest_is_stable_and_binds_exact_impact_semantics(self):
        increased = self._effect(
            "effect-impact-digest-increased",
            RiskDirection.INCREASED,
        )
        increased_future = self._resolved_with(
            (increased,),
            graph_id="graph-impact-digest-increased",
        )
        first = analyze_future_attack_path_impact(
            increased_future,
            self.f.state,
            self.client,
            current=self.f.current,
        )
        repeated = analyze_future_attack_path_impact(
            increased_future,
            self.f.state,
            self.client,
            current=self.f.current,
        )

        self.assertEqual(first.analysis_sha256, repeated.analysis_sha256)
        self.assertEqual(len(first.analysis_sha256), 64)
        int(first.analysis_sha256, 16)

        decreased = self._effect(
            "effect-impact-digest-decreased",
            RiskDirection.DECREASED,
        )
        decreased_future = self._resolved_with(
            (decreased,),
            graph_id="graph-impact-digest-decreased",
        )
        second = analyze_future_attack_path_impact(
            decreased_future,
            self.f.state,
            self.client,
            current=self.f.current,
        )

        self.assertNotEqual(first.analysis_sha256, second.analysis_sha256)
        self.assertEqual(first.items[0].impact, "potential_regression")
        self.assertEqual(second.items[0].impact, "potential_improvement")

    def test_report_validator_rejects_digest_and_boundary_tampering(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-validator",
        )
        report = analyze_future_attack_path_impact(
            resolved,
            self.f.state,
            self.client,
            current=self.f.current,
        )
        validate_future_attack_path_impact_report(report)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_future_attack_path_impact_report(
                dataclasses.replace(report, analysis_sha256="0" * 64)
            )

        tampered_item = dataclasses.replace(
            report.items[0],
            impact="potential_improvement",
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_future_attack_path_impact_report(
                dataclasses.replace(report, items=(tampered_item,))
            )

        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            validate_future_attack_path_impact_report(
                dataclasses.replace(report, security_verdict="approved")
            )

        with self.assertRaisesRegex(ValueError, "preserve unresolved"):
            validate_future_attack_path_impact_report(
                dataclasses.replace(report, future_semantics="resolved")
            )

    def test_serialized_report_round_trip_is_strict_and_digest_validated(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-round-trip",
        )
        report = analyze_future_attack_path_impact(
            resolved,
            self.f.state,
            self.client,
            current=self.f.current,
        )
        payload = json.loads(json.dumps(report.as_dict()))
        restored = future_attack_path_impact_report_from_dict(payload)
        self.assertEqual(restored, report)

        extra = dict(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_attack_path_impact_report_from_dict(extra)

        missing = dict(payload)
        missing.pop("changeset_id")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_attack_path_impact_report_from_dict(missing)

        tampered = json.loads(json.dumps(payload))
        tampered["items"][0]["impact"] = "potential_improvement"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_attack_path_impact_report_from_dict(tampered)

        wrong_shape = json.loads(json.dumps(payload))
        wrong_shape["items"] = {"not": "a list"}
        with self.assertRaisesRegex(ValueError, "items must be a list"):
            future_attack_path_impact_report_from_dict(wrong_shape)

    def test_deleted_graph_evidence_is_rejected_on_read(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-deleted-evidence",
        )
        with self.f.state.connect() as connection:
            connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (self.f.materialization_evidence_id,),
            )

        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            analyze_future_attack_path_impact(
                resolved,
                self.f.state,
                self.client,
                current=self.f.current,
            )

    def test_cross_tenant_access_fails_before_ledger_lookup(self):
        resolved = self._resolved_with(
            (self.f.effect,),
            graph_id="graph-impact-tenant",
        )
        other = AccessContext("other", Role.CLIENT_ADMIN, "client-2")
        with patch.object(self.f.state, "get_evidence") as lookup:
            with self.assertRaises(TenantIsolationError):
                analyze_future_attack_path_impact(
                    resolved,
                    self.f.state,
                    other,
                    current=self.f.current,
                )
            lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
