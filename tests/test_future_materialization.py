from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.ai.orchestration import RunContext
from lightup.changes import derive_future_twin
from lightup.future_materialization import (
    EnvironmentEquivalence,
    FutureMaterializationResolution,
    MaterializationOutcome,
    apply_future_materialization_resolution,
)
from lightup.github_changes import github_pull_request_changeset
from lightup.state import StateStore
from lightup.twin import FactProvenance, SecurityTwin, TwinNodeKind


class FutureMaterializationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.current = SecurityTwin.current("client-1")
        self.changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=101,
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
            engagement_id="future-materialization",
            client_id="client-1",
        )
        self.evidence_id = self.state.add_evidence(
            self.run_id,
            "web",
            "future-materialization-observation",
            "lab-fixture",
            b'{"route":"/admin/export","observed":true}',
            metadata={"asset": "127.0.0.1"},
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _resolution(
        self,
        *,
        outcome: MaterializationOutcome = MaterializationOutcome.CONFIRMED,
        equivalence: EnvironmentEquivalence = EnvironmentEquivalence.REPRESENTATIVE,
        evidence_ids: tuple[str, ...] | None = None,
        capability_ids: tuple[str, ...] = ("web",),
    ) -> FutureMaterializationResolution:
        return FutureMaterializationResolution(
            resolution_id="resolution-1",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            run_id=self.run_id,
            outcome=outcome,
            equivalence=equivalence,
            evidence_ids=evidence_ids or (self.evidence_id,),
            capability_ids=capability_ids,
            limitations=("isolated fixture; production reachability not asserted",),
        )

    def test_confirmed_lab_resolution_adds_verified_outcome_only(self):
        resolved = apply_future_materialization_resolution(
            self.future,
            self._resolution(),
            self.context,
            self.state,
        )

        original_change_facts = [
            fact
            for fact in resolved.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate.startswith("change.")
        ]
        self.assertTrue(original_change_facts)
        self.assertTrue(
            all(
                fact.provenance is FactProvenance.INFERRED
                for fact in original_change_facts
            )
        )

        outcome = next(
            fact
            for fact in resolved.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate == "materialization.outcome"
        )
        self.assertEqual(outcome.value, "confirmed")
        self.assertIs(outcome.provenance, FactProvenance.VERIFIED)
        self.assertEqual(outcome.evidence_refs, (f"evidence:{self.evidence_id}",))
        self.assertEqual(resolved.relationships, self.future.relationships)
        self.assertEqual(resolved.attack_paths, self.future.attack_paths)
        self.assertEqual(self.current.nodes, ())
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        self.assertEqual(
            dict(resolved.metadata)["future_materialization_confirmed_count"], "1"
        )

    def test_non_lab_context_is_rejected(self):
        import dataclasses

        forged = dataclasses.replace(self.context, is_lab=False)
        with self.assertRaises(PermissionError):
            apply_future_materialization_resolution(
                self.future,
                self._resolution(),
                forged,
                self.state,
            )

    def test_cross_tenant_context_is_rejected(self):
        other = RunContext.for_lab(
            self.run_id,
            engagement_id="future-materialization",
            client_id="client-2",
        )
        with self.assertRaises(ValueError):
            apply_future_materialization_resolution(
                self.future,
                self._resolution(),
                other,
                self.state,
            )

    def test_evidence_from_another_run_is_rejected(self):
        other_run = self.state.create_run(
            "127.0.0.1",
            activation_mode="lab_autonomous",
        )
        other_evidence = self.state.add_evidence(
            other_run,
            "web",
            "future-materialization-observation",
            "lab-fixture",
            b"other",
        )
        with self.assertRaises(ValueError):
            apply_future_materialization_resolution(
                self.future,
                self._resolution(evidence_ids=(other_evidence,)),
                self.context,
                self.state,
            )

    def test_capability_claim_must_match_evidence(self):
        with self.assertRaises(ValueError):
            apply_future_materialization_resolution(
                self.future,
                self._resolution(capability_ids=("cloud",)),
                self.context,
                self.state,
            )

    def test_confirmed_unknown_equivalence_fails_closed(self):
        with self.assertRaises(ValueError):
            self._resolution(
                equivalence=EnvironmentEquivalence.UNKNOWN
            ).validate()

    def test_not_observed_is_evidence_backed_but_not_confirmation(self):
        resolved = apply_future_materialization_resolution(
            self.future,
            self._resolution(
                outcome=MaterializationOutcome.NOT_OBSERVED,
                equivalence=EnvironmentEquivalence.PARTIAL,
            ),
            self.context,
            self.state,
        )
        outcome = next(
            fact for fact in resolved.facts
            if fact.predicate == "materialization.outcome"
        )
        self.assertEqual(outcome.value, "not_observed")
        self.assertIs(outcome.provenance, FactProvenance.VERIFIED)
        metadata = dict(resolved.metadata)
        self.assertEqual(metadata["future_materialization_confirmed_count"], "0")
        self.assertEqual(metadata["future_semantics"], "unresolved")

    def test_same_resolution_is_idempotent(self):
        resolution = self._resolution()
        resolved = apply_future_materialization_resolution(
            self.future, resolution, self.context, self.state
        )
        repeated = apply_future_materialization_resolution(
            resolved, resolution, self.context, self.state
        )
        self.assertIs(repeated, resolved)


if __name__ == "__main__":
    unittest.main()
