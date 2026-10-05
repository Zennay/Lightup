from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_analysis as impact_tests
from lightup.attack_graph_delta_readiness import (
    build_attack_graph_delta_readiness,
    validate_attack_graph_delta_readiness_report,
)
from lightup.domain import AccessContext, Role, TenantIsolationError
from lightup.future_attack_path_analysis import analyze_future_attack_path_impact
from lightup.future_effects import RiskDirection
from lightup.twin import AttackPath, AttackStep


class AttackGraphDeltaReadinessTest(unittest.TestCase):
    def setUp(self):
        self.f = impact_tests.FutureAttackPathImpactAnalysisTest(
            "test_analysis_digest_is_stable_and_binds_exact_impact_semantics"
        )
        self.f.setUp()
        self.addCleanup(self.f.tearDown)

    def _future_and_report(self, direction: RiskDirection, *, suffix: str):
        effect = self.f._effect(f"effect-st4-{suffix}", direction)
        future = self.f._resolved_with(
            (effect,),
            graph_id=f"graph-st4-{suffix}",
        )
        report = analyze_future_attack_path_impact(
            future,
            self.f.f.state,
            self.f.client,
            current=self.f.f.current,
        )
        return future, report

    def test_regression_without_current_path_stays_unknown_not_introduced(self):
        future, impact = self._future_and_report(
            RiskDirection.INCREASED,
            suffix="new-path",
        )
        before_current = dataclasses.asdict(self.f.f.current)
        before_future = dataclasses.asdict(future)

        readiness = build_attack_graph_delta_readiness(
            impact,
            current=self.f.f.current,
            future=future,
            context=self.f.client,
        )

        self.assertTrue(readiness.readiness_assessed)
        self.assertFalse(readiness.attack_path_mutation_allowed)
        self.assertEqual(readiness.security_verdict, "not_evaluated")
        self.assertEqual(readiness.future_semantics, "unresolved")
        self.assertEqual(readiness.impact_analysis_sha256, impact.analysis_sha256)
        self.assertEqual(len(readiness.items), 1)
        item = readiness.items[0]
        self.assertEqual(item.current_attack_path_ids, ())
        self.assertEqual(item.impact_hint, "potential_regression")
        self.assertEqual(item.candidate_direction_hint, "potential_worsening")
        self.assertEqual(item.verified_delta_classification, "unknown")
        self.assertEqual(
            item.verification_state,
            "insufficient_future_path_evidence",
        )
        self.assertNotEqual(item.verified_delta_classification, "introduced")
        self.assertEqual(dataclasses.asdict(self.f.f.current), before_current)
        self.assertEqual(dataclasses.asdict(future), before_future)

    def test_existing_path_membership_is_preserved_but_not_classified(self):
        path = AttackPath(
            path_id="path-st4-existing",
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
        future = self.f._resolved_from_current(
            current,
            graph_id="graph-st4-existing",
        )
        impact = analyze_future_attack_path_impact(
            future,
            self.f.f.state,
            self.f.client,
            current=current,
        )

        readiness = build_attack_graph_delta_readiness(
            impact,
            current=current,
            future=future,
            context=self.f.client,
        )

        self.assertEqual(
            readiness.items[0].current_attack_path_ids,
            ("path-st4-existing",),
        )
        self.assertEqual(
            readiness.items[0].verified_delta_classification,
            "unknown",
        )

    def test_all_st3_impact_hints_remain_unknown(self):
        cases = (
            (RiskDirection.INCREASED, "potential_worsening", "increased"),
            (RiskDirection.DECREASED, "potential_improvement", "decreased"),
            (RiskDirection.UNCHANGED, "unchanged", "unchanged"),
        )
        for direction, hint, suffix in cases:
            with self.subTest(direction=direction.value):
                future, impact = self._future_and_report(direction, suffix=suffix)
                readiness = build_attack_graph_delta_readiness(
                    impact,
                    current=self.f.f.current,
                    future=future,
                    context=self.f.client,
                )
                item = readiness.items[0]
                self.assertEqual(item.candidate_direction_hint, hint)
                self.assertEqual(item.verified_delta_classification, "unknown")

        decreased = self.f._effect(
            "effect-st4-mixed-decreased",
            RiskDirection.DECREASED,
        )
        mixed_future = self.f._resolved_with(
            (self.f.f.effect, decreased),
            graph_id="graph-st4-mixed",
        )
        mixed_impact = analyze_future_attack_path_impact(
            mixed_future,
            self.f.f.state,
            self.f.client,
            current=self.f.f.current,
        )
        mixed = build_attack_graph_delta_readiness(
            mixed_impact,
            current=self.f.f.current,
            future=mixed_future,
            context=self.f.client,
        )
        self.assertEqual(mixed.items[0].candidate_direction_hint, "mixed")
        self.assertEqual(mixed.items[0].verified_delta_classification, "unknown")

    def test_cross_tenant_rejects_before_twin_validation(self):
        future, impact = self._future_and_report(
            RiskDirection.INCREASED,
            suffix="tenant",
        )
        invalid_current = dataclasses.replace(self.f.f.current, version=0)
        other = AccessContext("other", Role.CLIENT_ADMIN, "client-2")

        with self.assertRaises(TenantIsolationError):
            build_attack_graph_delta_readiness(
                impact,
                current=invalid_current,
                future=future,
                context=other,
            )

    def test_exact_current_and_future_identity_are_required(self):
        future, impact = self._future_and_report(
            RiskDirection.INCREASED,
            suffix="identity",
        )
        wrong_current = dataclasses.replace(
            self.f.f.current,
            twin_id="wrong-current",
        )
        with self.assertRaisesRegex(ValueError, "supplied Current Twin"):
            build_attack_graph_delta_readiness(
                impact,
                current=wrong_current,
                future=future,
                context=self.f.client,
            )

        wrong_future = dataclasses.replace(
            future,
            twin_id="wrong-future",
        )
        with self.assertRaisesRegex(ValueError, "supplied Future Twin"):
            build_attack_graph_delta_readiness(
                impact,
                current=self.f.f.current,
                future=wrong_future,
                context=self.f.client,
            )

    def test_baseline_changeset_and_attack_path_drift_fail_closed(self):
        future, impact = self._future_and_report(
            RiskDirection.INCREASED,
            suffix="lineage",
        )

        metadata = dict(future.metadata)
        metadata["future_base_twin_sha256"] = "0" * 64
        wrong_lineage = dataclasses.replace(
            future,
            metadata=tuple(sorted(metadata.items())),
        )
        with self.assertRaisesRegex(ValueError, "baseline lineage"):
            build_attack_graph_delta_readiness(
                impact,
                current=self.f.f.current,
                future=wrong_lineage,
                context=self.f.client,
            )

        metadata = dict(future.metadata)
        metadata["changeset_id"] = "wrong-changeset"
        wrong_changeset = dataclasses.replace(
            future,
            metadata=tuple(sorted(metadata.items())),
        )
        with self.assertRaisesRegex(ValueError, "ChangeSet"):
            build_attack_graph_delta_readiness(
                impact,
                current=self.f.f.current,
                future=wrong_changeset,
                context=self.f.client,
            )

        drift = AttackPath(
            path_id="path-st4-drift",
            title="Unexpected future path",
            steps=(
                AttackStep(
                    source_id=self.f.f.subject.node_id,
                    target_id=self.f.f.subject.node_id,
                    relation="unexpected_future_transition",
                ),
            ),
        )
        wrong_paths = dataclasses.replace(
            future,
            attack_paths=future.attack_paths + (drift,),
        )
        with self.assertRaisesRegex(ValueError, "attack paths unchanged"):
            build_attack_graph_delta_readiness(
                impact,
                current=self.f.f.current,
                future=wrong_paths,
                context=self.f.client,
            )

    def test_report_digest_is_deterministic_and_tamper_evident(self):
        future, impact = self._future_and_report(
            RiskDirection.INCREASED,
            suffix="digest",
        )
        first = build_attack_graph_delta_readiness(
            impact,
            current=self.f.f.current,
            future=future,
            context=self.f.client,
        )
        second = build_attack_graph_delta_readiness(
            impact,
            current=self.f.f.current,
            future=future,
            context=self.f.client,
        )

        self.assertEqual(first, second)
        self.assertEqual(len(first.report_sha256), 64)
        int(first.report_sha256, 16)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_attack_graph_delta_readiness_report(
                dataclasses.replace(first, report_sha256="0" * 64)
            )

        forged_item = dataclasses.replace(
            first.items[0],
            verified_delta_classification="worsened",
        )
        with self.assertRaisesRegex(ValueError, "cannot claim a verified path delta"):
            validate_attack_graph_delta_readiness_report(
                dataclasses.replace(first, items=(forged_item,))
            )


if __name__ == "__main__":
    unittest.main()
