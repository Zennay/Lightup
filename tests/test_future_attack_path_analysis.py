from __future__ import annotations

import dataclasses
import json
import unittest
from unittest.mock import patch

import test_future_graph_resolution as graph_tests
from lightup.domain import AccessContext, Role, TenantIsolationError
from lightup.future_attack_path_analysis import analyze_future_attack_path_impact
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
        include_existing_path: bool = False,
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

        if include_existing_path:
            path = AttackPath(
                path_id="path-existing-1",
                title="Existing path through reviewed API",
                steps=(
                    AttackStep(
                        source_id=self.f.subject.node_id,
                        target_id=self.f.change_node.node_id,
                        relation="existing_dependency",
                    ),
                ),
                evidence_refs=("evidence:existing-path",),
            )
            future = future.next_snapshot(
                attack_paths=future.attack_paths + (path,)
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
        resolved = self._resolved_with(
            (self.f.effect,),
            include_existing_path=True,
            graph_id="graph-impact-increased",
        )
        before = dataclasses.asdict(resolved)
        report = analyze_future_attack_path_impact(
            resolved, self.f.state, self.client
        )

        self.assertTrue(report.analysis_complete)
        self.assertEqual(report.security_verdict, "not_evaluated")
        self.assertEqual(report.future_semantics, "unresolved")
        self.assertEqual(len(report.items), 1)
        item = report.items[0]
        self.assertEqual(item.impact, "potential_regression")
        self.assertEqual(item.risk_directions, ("increased",))
        self.assertEqual(item.current_attack_path_ids, ("path-existing-1",))
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
            resolved, self.f.state, self.client
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
            mixed, self.f.state, self.client
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
            unchanged_resolved, self.f.state, self.client
        )
        self.assertEqual(unchanged_report.items[0].impact, "unchanged")

    def test_unresolved_graph_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "complete verified graph"):
            analyze_future_attack_path_impact(
                self.f.reviewed,
                self.f.state,
                self.client,
            )

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
                )
            lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
