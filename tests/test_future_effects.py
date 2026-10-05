from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.ai.orchestration import RunContext
from lightup.changes import derive_future_twin
from lightup.future_effects import (
    FutureSecurityEffect,
    RiskDirection,
    SecurityEffectKind,
    apply_future_security_effects,
)
from lightup.future_materialization import (
    EnvironmentEquivalence,
    FutureMaterializationResolution,
    MaterializationOutcome,
    apply_future_materialization_resolution,
)
from lightup.github_changes import github_pull_request_changeset
from lightup.state import StateStore
from lightup.twin import FactProvenance, SecurityTwin, TwinNodeKind


class FutureSecurityEffectsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.current = SecurityTwin.current("client-1")
        self.changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=130,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.yaml",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                    "patch": "@@ -1,0 +1 @@\n+/admin/export:",
                },
            ),
        )
        self.future = derive_future_twin(self.current, self.changeset)
        self.change_node = next(
            node for node in self.future.nodes if node.kind is TwinNodeKind.CHANGE
        )
        self.run_id = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        self.context = RunContext.for_lab(
            self.run_id,
            engagement_id="future-effects",
            client_id="client-1",
        )
        self.evidence_id = self.state.add_evidence(
            self.run_id,
            "web",
            "future-materialization-observation",
            "lab-fixture",
            b'{"route":"/admin/export","observed":true}',
            metadata={
                "asset": "127.0.0.1",
                "client_id": "client-1",
                "engagement_id": "future-effects",
                "mode": "lab_autonomous",
                "is_lab": "true",
            },
        )
        self.resolution = FutureMaterializationResolution(
            resolution_id="resolution-1",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            run_id=self.run_id,
            outcome=MaterializationOutcome.CONFIRMED,
            equivalence=EnvironmentEquivalence.REPRESENTATIVE,
            evidence_ids=(self.evidence_id,),
            capability_ids=("web",),
            limitations=("isolated fixture; production reachability not asserted",),
        )
        self.materialized = apply_future_materialization_resolution(
            self.future,
            self.resolution,
            self.context,
            self.state,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _effect(self, **overrides):
        values = {
            "effect_id": "effect-1",
            "resolution_id": self.resolution.resolution_id,
            "client_id": "client-1",
            "changeset_id": self.changeset.changeset_id,
            "change_node_id": self.change_node.node_id,
            "capability_id": "web",
            "kind": SecurityEffectKind.ATTACK_SURFACE_ADDED,
            "risk_direction": RiskDirection.INCREASED,
            "evidence_ids": (self.evidence_id,),
        }
        values.update(overrides)
        return FutureSecurityEffect(**values)

    def test_verified_effects_are_recorded_without_graph_promotion(self):
        resolved = apply_future_security_effects(
            self.materialized,
            self.resolution,
            (self._effect(),),
        )

        effect_facts = [
            fact
            for fact in resolved.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate.startswith("future_effect.")
        ]
        self.assertEqual(len(effect_facts), 4)
        self.assertTrue(
            all(fact.provenance is FactProvenance.VERIFIED for fact in effect_facts)
        )
        self.assertTrue(
            all(
                fact.evidence_refs == (f"evidence:{self.evidence_id}",)
                for fact in effect_facts
            )
        )
        self.assertEqual(resolved.relationships, self.materialized.relationships)
        self.assertEqual(resolved.attack_paths, self.materialized.attack_paths)
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        self.assertEqual(
            dict(resolved.metadata)["future_security_effect_count"],
            "1",
        )

    def test_effects_require_materialization_to_be_applied_first(self):
        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.future,
                self.resolution,
                (self._effect(),),
            )

    def test_non_confirmed_materialization_cannot_create_verified_effect(self):
        inconclusive = FutureMaterializationResolution(
            resolution_id="resolution-2",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            run_id=self.run_id,
            outcome=MaterializationOutcome.INCONCLUSIVE,
            equivalence=EnvironmentEquivalence.PARTIAL,
            evidence_ids=(self.evidence_id,),
            capability_ids=("web",),
        )
        inconclusive_future = apply_future_materialization_resolution(
            self.future,
            inconclusive,
            self.context,
            self.state,
        )
        effect = self._effect(resolution_id="resolution-2")

        with self.assertRaises(ValueError):
            apply_future_security_effects(
                inconclusive_future,
                inconclusive,
                (effect,),
            )

    def test_effect_evidence_must_be_subset_of_materialization_evidence(self):
        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.materialized,
                self.resolution,
                (self._effect(evidence_ids=("other-evidence",)),),
            )

    def test_effect_capability_must_have_been_materialized(self):
        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.materialized,
                self.resolution,
                (self._effect(capability_id="cloud"),),
            )

    def test_forged_resolution_cannot_expand_materialized_capabilities(self):
        import dataclasses

        forged = dataclasses.replace(
            self.resolution,
            capability_ids=("web", "cloud"),
        )

        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.materialized,
                forged,
                (self._effect(capability_id="cloud"),),
            )

    def test_resolution_identity_and_tenant_must_match(self):
        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.materialized,
                self.resolution,
                (self._effect(resolution_id="other-resolution"),),
            )
        with self.assertRaises(ValueError):
            apply_future_security_effects(
                self.materialized,
                self.resolution,
                (self._effect(client_id="client-2"),),
            )

    def test_same_effect_is_idempotent(self):
        effect = self._effect()
        once = apply_future_security_effects(
            self.materialized,
            self.resolution,
            (effect,),
        )
        twice = apply_future_security_effects(
            once,
            self.resolution,
            (effect,),
        )
        self.assertIs(twice, once)

    def test_same_effect_id_with_conflicting_semantics_fails_closed(self):
        once = apply_future_security_effects(
            self.materialized,
            self.resolution,
            (self._effect(),),
        )
        conflicting = self._effect(kind=SecurityEffectKind.CONTROL_STRENGTHENED)

        with self.assertRaises(ValueError):
            apply_future_security_effects(
                once,
                self.resolution,
                (conflicting,),
            )


if __name__ == "__main__":
    unittest.main()
