from __future__ import annotations

import dataclasses
import hashlib
import tempfile
import unittest
from pathlib import Path

from lightup.changes import derive_future_twin
from lightup.future_subject_resolution import (
    FutureSubjectResolution,
    SubjectResolutionBasis,
    apply_future_subject_resolution,
)
from lightup.github_changes import github_pull_request_changeset
from lightup.state import StateStore
from lightup.twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNode,
    TwinNodeKind,
    TwinRelationship,
)


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(material).hexdigest()[:24]}"


class FutureSubjectResolutionTest(unittest.TestCase):
    def setUp(self):
        self.subject = TwinNode(
            "api-1",
            TwinNodeKind.API,
            "Admin API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        self.current = SecurityTwin.current("client-1").next_snapshot(
            nodes=(self.subject,)
        )
        self.changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=140,
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
        self.signal_evidence_refs = self.changeset.semantic_signals[0].evidence_refs
        self.candidate = TwinRelationship(
            relationship_id=_stable_id(
                "relationship",
                self.change_node.node_id,
                self.subject.node_id,
                "candidate_affects",
            ),
            source_id=self.change_node.node_id,
            target_id=self.subject.node_id,
            relation="candidate_affects",
            provenance=FactProvenance.INFERRED,
            confidence=0.75,
            evidence_refs=self.signal_evidence_refs,
        )
        self.candidate_evidence_sha256 = hashlib.sha256(
            "\x1f".join(sorted(self.candidate.evidence_refs)).encode("utf-8")
        ).hexdigest()
        self.binding_status = TwinFact(
            fact_id=_stable_id(
                "fact", self.change_node.node_id, "change.binding_status"
            ),
            subject_id=self.change_node.node_id,
            predicate="change.binding_status",
            value="single_candidate",
            provenance=FactProvenance.INFERRED,
            confidence=1.0,
            evidence_refs=self.candidate.evidence_refs,
        )
        self.binding_count = TwinFact(
            fact_id=_stable_id(
                "fact", self.change_node.node_id, "change.candidate_count"
            ),
            subject_id=self.change_node.node_id,
            predicate="change.candidate_count",
            value="1",
            provenance=FactProvenance.INFERRED,
            confidence=1.0,
            evidence_refs=self.candidate.evidence_refs,
        )
        bound_snapshot = self.future.next_snapshot(
            facts=self.future.facts + (self.binding_status, self.binding_count),
            relationships=self.future.relationships + (self.candidate,),
        )
        bound_metadata = dict(bound_snapshot.metadata)
        bound_metadata.update(
            {
                "future_subject_binding": "exact_source_metadata",
                "future_subject_binding_count": "1",
                "future_subject_binding_ambiguous": "0",
                "future_subject_binding_missing": "0",
                "future_semantics": "unresolved",
            }
        )
        self.bound = dataclasses.replace(
            bound_snapshot,
            metadata=tuple(sorted(bound_metadata.items())),
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.run_id = self.state.create_run(
            "subject-resolution",
            activation_mode="plan_only",
        )
        self.rationale = "Repository path and reviewed ownership mapping agree."
        self.evidence_id = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"subject api-1 reviewed for change",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": self.bound.twin_id,
                "future_twin_version": str(self.bound.version),
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
        self.resolution = FutureSubjectResolution(
            decision_id="decision-1",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=self.change_node.node_id,
            subject_node_id=self.subject.node_id,
            run_id=self.run_id,
            basis=SubjectResolutionBasis.OPERATOR_REVIEWED,
            evidence_ids=(self.evidence_id,),
            rationale=self.rationale,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_verified_subject_resolution_preserves_candidate_and_attack_paths(self):
        resolved = apply_future_subject_resolution(self.bound, self.resolution, self.state)

        links = [
            relationship
            for relationship in resolved.relationships
            if relationship.relation == "verified_affects_subject"
        ]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].source_id, self.change_node.node_id)
        self.assertEqual(links[0].target_id, self.subject.node_id)
        self.assertIs(links[0].provenance, FactProvenance.VERIFIED)
        self.assertEqual(
            links[0].evidence_refs,
            (f"evidence:{self.evidence_id}",),
        )
        self.assertIn(self.candidate, resolved.relationships)
        self.assertEqual(resolved.attack_paths, self.bound.attack_paths)
        self.assertEqual(dict(resolved.metadata)["future_semantics"], "unresolved")
        self.assertEqual(
            dict(resolved.metadata)["future_subject_resolution_count"],
            "1",
        )

    def test_resolution_requires_existing_inferred_candidate_link(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.future, self.resolution, self.state)

    def test_verified_subject_relationship_cannot_hide_inferred_provenance(self):
        forged_relationship = TwinRelationship(
            relationship_id="forged-verified-subject-link",
            source_id=self.change_node.node_id,
            target_id=self.subject.node_id,
            relation="verified_affects_subject",
            provenance=FactProvenance.INFERRED,
            confidence=1.0,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged = self.bound.next_snapshot(
            relationships=self.bound.relationships + (forged_relationship,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_verified_subject_fact_cannot_hide_inferred_provenance(self):
        forged_fact = TwinFact(
            fact_id="forged-future-subject-state",
            subject_id=self.change_node.node_id,
            predicate="future_subject.node_id",
            value=self.subject.node_id,
            provenance=FactProvenance.INFERRED,
            confidence=1.0,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged = self.bound.next_snapshot(
            facts=self.bound.facts + (forged_fact,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_verified_subject_relationship_must_originate_from_change(self):
        forged_relationship = TwinRelationship(
            relationship_id="forged-verified-subject-link",
            source_id=self.subject.node_id,
            target_id=self.subject.node_id,
            relation="verified_affects_subject",
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.update(
            {
                "future_subject_resolution": "evidence_recorded",
                "future_subject_resolution_count": "1",
            }
        )
        forged = dataclasses.replace(
            self.bound,
            relationships=self.bound.relationships + (forged_relationship,),
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_verified_subject_fact_must_belong_to_change(self):
        forged_fact = TwinFact(
            fact_id="forged-future-subject-state-on-api",
            subject_id=self.subject.node_id,
            predicate="future_subject.node_id",
            value=self.subject.node_id,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged = self.bound.next_snapshot(
            facts=self.bound.facts + (forged_fact,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_verified_subject_state_requires_full_confidence(self):
        forged_fact = TwinFact(
            fact_id="forged-low-confidence-future-subject",
            subject_id=self.change_node.node_id,
            predicate="future_subject.node_id",
            value=self.subject.node_id,
            provenance=FactProvenance.VERIFIED,
            confidence=0.5,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged = self.bound.next_snapshot(
            facts=self.bound.facts + (forged_fact,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_orphan_verified_subject_state_on_sibling_change_fails_closed(self):
        other_change = dataclasses.replace(
            self.change_node,
            node_id="change:sibling-partial-subject",
        )
        other_evidence = ("evidence:sibling-change-signal",)
        other_status = dataclasses.replace(
            self.binding_status,
            fact_id="binding-status-sibling-partial-subject",
            subject_id=other_change.node_id,
            value="no_candidate",
            evidence_refs=other_evidence,
        )
        other_count = dataclasses.replace(
            self.binding_count,
            fact_id="binding-count-sibling-partial-subject",
            subject_id=other_change.node_id,
            value="0",
            evidence_refs=other_evidence,
        )
        forged_subject_fact = TwinFact(
            fact_id="forged-sibling-future-subject-node",
            subject_id=other_change.node_id,
            predicate="future_subject.node_id",
            value=self.subject.node_id,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=("evidence:forged-sibling-subject-state",),
        )
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.update(
            {
                "future_subject_binding_count": "2",
                "future_subject_binding_ambiguous": "0",
                "future_subject_binding_missing": "1",
            }
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=self.bound.nodes + (other_change,),
            facts=self.bound.facts
            + (other_status, other_count, forged_subject_fact),
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaisesRegex(ValueError, "partial verified subject state"):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_verified_subject_state_rejects_unknown_predicate(self):
        resolved = apply_future_subject_resolution(
            self.bound,
            self.resolution,
            self.state,
        )
        forged_fact = TwinFact(
            fact_id="forged-extra-future-subject-fact",
            subject_id=self.change_node.node_id,
            predicate="future_subject.untrusted_hint",
            value="ignored",
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=(f"evidence:{self.evidence_id}",),
        )
        forged = resolved.next_snapshot(
            facts=resolved.facts + (forged_fact,),
        )

        with self.assertRaisesRegex(
            ValueError,
            "unknown verified future_subject predicate",
        ):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_existing_verified_subject_fact_values_must_be_canonical(self):
        resolved = apply_future_subject_resolution(
            self.bound,
            self.resolution,
            self.state,
        )
        cases = (
            ("future_subject.decision_id", " decision-1 "),
            ("future_subject.run_id", f" {self.run_id}"),
            ("future_subject.basis", "model_guess"),
            ("future_subject.rationale_sha256", "A" * 64),
            ("future_subject.candidate_evidence_sha256", "g" * 64),
        )
        for predicate, forged_value in cases:
            with self.subTest(predicate=predicate, forged_value=forged_value):
                forged = resolved.next_snapshot(
                    facts=tuple(
                        dataclasses.replace(fact, value=forged_value)
                        if fact.predicate == predicate
                        else fact
                        for fact in resolved.facts
                    ),
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_verified_subject_state_rejects_stale_candidate_evidence(self):
        resolved = apply_future_subject_resolution(
            self.bound,
            self.resolution,
            self.state,
        )
        stale_refs = ("evidence:replacement-change-signal",)
        forged = resolved.next_snapshot(
            facts=tuple(
                dataclasses.replace(fact, evidence_refs=stale_refs)
                if fact.subject_id == self.change_node.node_id
                and fact.predicate in {
                    "change.signal_kind", "change.direction", "change.summary",
                    "change.binding_status", "change.candidate_count",
                }
                else fact
                for fact in resolved.facts
            ),
            relationships=tuple(
                dataclasses.replace(relationship, evidence_refs=stale_refs)
                if relationship.relationship_id == self.candidate.relationship_id
                else relationship
                for relationship in resolved.relationships
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "stale against current candidate evidence",
        ):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_verified_subject_state_rejects_retargeted_candidate(self):
        resolved = apply_future_subject_resolution(
            self.bound,
            self.resolution,
            self.state,
        )
        other_subject = TwinNode(
            "api-retargeted",
            TwinNodeKind.API,
            "Retargeted API",
        )
        retargeted_candidate = dataclasses.replace(
            self.candidate,
            relationship_id=_stable_id(
                "relationship", self.change_node.node_id,
                other_subject.node_id, "candidate_affects",
            ),
            target_id=other_subject.node_id,
        )
        forged = resolved.next_snapshot(
            nodes=resolved.nodes + (other_subject,),
            relationships=tuple(
                retargeted_candidate
                if relationship.relationship_id == self.candidate.relationship_id
                else relationship
                for relationship in resolved.relationships
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "stale against current candidate binding",
        ):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_existing_verified_sibling_requires_live_ledger_evidence(self):
        other_subject = TwinNode(
            "api-sibling-ledger",
            TwinNodeKind.API,
            "Sibling Ledger API",
        )
        sibling_signal_id = "signal:sibling-ledger"
        sibling_attributes = dict(self.change_node.attributes)
        sibling_attributes["signal_id"] = sibling_signal_id
        other_change = dataclasses.replace(
            self.change_node,
            node_id=_stable_id(
                "change", self.changeset.changeset_id, sibling_signal_id
            ),
            attributes=tuple(sorted(sibling_attributes.items())),
        )
        other_candidate_refs = self.signal_evidence_refs
        other_candidate = TwinRelationship(
            relationship_id=_stable_id(
                "relationship",
                other_change.node_id,
                other_subject.node_id,
                "candidate_affects",
            ),
            source_id=other_change.node_id,
            target_id=other_subject.node_id,
            relation="candidate_affects",
            provenance=FactProvenance.INFERRED,
            confidence=0.75,
            evidence_refs=other_candidate_refs,
        )
        other_status = dataclasses.replace(
            self.binding_status,
            fact_id=_stable_id(
                "fact", other_change.node_id, "change.binding_status"
            ),
            subject_id=other_change.node_id,
            evidence_refs=other_candidate_refs,
        )
        other_count = dataclasses.replace(
            self.binding_count,
            fact_id=_stable_id(
                "fact", other_change.node_id, "change.candidate_count"
            ),
            subject_id=other_change.node_id,
            evidence_refs=other_candidate_refs,
        )
        other_signal_facts = tuple(
            dataclasses.replace(
                fact,
                fact_id=_stable_id(
                    "fact", other_change.node_id, fact.predicate, fact.value
                ),
                subject_id=other_change.node_id,
                evidence_refs=other_candidate_refs,
            )
            for fact in self.future.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate in {
                "change.signal_kind",
                "change.direction",
                "change.summary",
            }
        )
        base_metadata = dict(self.bound.metadata)
        base_metadata.update(
            {
                "future_subject_binding_count": "2",
                "future_subject_binding_ambiguous": "0",
                "future_subject_binding_missing": "0",
            }
        )
        base = dataclasses.replace(
            self.bound,
            nodes=self.bound.nodes + (other_change, other_subject),
            facts=self.bound.facts + other_signal_facts + (other_status, other_count),
            relationships=self.bound.relationships + (other_candidate,),
            metadata=tuple(sorted(base_metadata.items())),
        )
        other_rationale = "Sibling ownership mapping was independently reviewed."
        other_candidate_digest = hashlib.sha256(
            "\x1f".join(sorted(other_candidate_refs)).encode("utf-8")
        ).hexdigest()
        other_evidence_id = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"sibling subject reviewed",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-sibling-ledger",
                "client_id": "client-1",
                "future_twin_id": base.twin_id,
                "future_twin_version": str(base.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": other_change.node_id,
                "subject_node_id": other_subject.node_id,
                "candidate_evidence_sha256": other_candidate_digest,
                "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
                "rationale_sha256": hashlib.sha256(
                    other_rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        sibling_resolution = FutureSubjectResolution(
            decision_id="decision-sibling-ledger",
            client_id="client-1",
            changeset_id=self.changeset.changeset_id,
            change_node_id=other_change.node_id,
            subject_node_id=other_subject.node_id,
            run_id=self.run_id,
            basis=SubjectResolutionBasis.OPERATOR_REVIEWED,
            evidence_ids=(other_evidence_id,),
            rationale=other_rationale,
        )
        with_sibling = apply_future_subject_resolution(
            base,
            sibling_resolution,
            self.state,
        )
        with self.state.connect() as con:
            con.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (other_evidence_id,),
            )

        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            apply_future_subject_resolution(
                with_sibling,
                self.resolution,
                self.state,
            )

    def test_forged_candidate_without_binding_facts_fails_closed(self):
        forged = self.future.next_snapshot(
            relationships=self.future.relationships + (self.candidate,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_binding_state_must_be_single_candidate(self):
        ambiguous_status = dataclasses.replace(
            self.binding_status,
            value="ambiguous",
        )
        inconsistent = self.bound.next_snapshot(
            facts=tuple(
                fact
                for fact in self.bound.facts
                if fact.fact_id != self.binding_status.fact_id
            )
            + (ambiguous_status,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(inconsistent, self.resolution, self.state)

    def test_binding_evidence_lineage_must_match_candidate(self):
        mismatched_count = dataclasses.replace(
            self.binding_count,
            evidence_refs=("evidence:different-signal",),
        )
        inconsistent = self.bound.next_snapshot(
            facts=tuple(
                fact
                for fact in self.bound.facts
                if fact.fact_id != self.binding_count.fact_id
            )
            + (mismatched_count,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(inconsistent, self.resolution, self.state)

    def test_subject_resolution_rejects_incomplete_binding_state_on_other_change(self):
        other_change = dataclasses.replace(
            self.change_node,
            node_id="change:other",
        )
        other_status = dataclasses.replace(
            self.binding_status,
            fact_id="binding-status-other",
            subject_id=other_change.node_id,
            value="no_candidate",
        )
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.update(
            {
                "future_subject_binding_count": "2",
                "future_subject_binding_missing": "1",
            }
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=self.bound.nodes + (other_change,),
            facts=self.bound.facts + (other_status,),
            metadata=tuple(sorted(forged_metadata.items())),
        )
        forged.validate()

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_rejects_promoted_candidate_binding_facts(self):
        promoted_status = dataclasses.replace(
            self.binding_status,
            fact_id="binding-status-promoted",
            provenance=FactProvenance.VERIFIED,
            evidence_refs=("evidence:promoted-binding",),
        )
        promoted_count = dataclasses.replace(
            self.binding_count,
            fact_id="binding-count-promoted",
            provenance=FactProvenance.DECLARED,
            evidence_refs=(),
        )
        for extra_fact in (promoted_status, promoted_count):
            with self.subTest(predicate=extra_fact.predicate):
                forged = self.bound.next_snapshot(
                    facts=self.bound.facts + (extra_fact,),
                )
                forged.validate()

                with self.assertRaisesRegex(ValueError, "binding facts to remain inferred"):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_subject_resolution_requires_binding_facts_for_every_future_change(self):
        other_change = dataclasses.replace(
            self.change_node,
            node_id="change:unbound",
        )
        forged = self.bound.next_snapshot(
            nodes=self.bound.nodes + (other_change,),
        )
        forged.validate()

        with self.assertRaisesRegex(ValueError, "every future change"):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_rejects_verified_candidate_affects_state(self):
        other_change = dataclasses.replace(
            self.change_node,
            node_id="change:verified-candidate",
        )
        other_subject = TwinNode(
            "api-verified-candidate",
            TwinNodeKind.API,
            "Verified candidate API",
        )
        other_evidence = ("evidence:verified-candidate-binding",)
        other_status = dataclasses.replace(
            self.binding_status,
            fact_id="binding-status-verified-candidate",
            subject_id=other_change.node_id,
            value="no_candidate",
            evidence_refs=other_evidence,
        )
        other_count = dataclasses.replace(
            self.binding_count,
            fact_id="binding-count-verified-candidate",
            subject_id=other_change.node_id,
            value="0",
            evidence_refs=other_evidence,
        )
        verified_candidate = TwinRelationship(
            relationship_id="verified-candidate-affects",
            source_id=other_change.node_id,
            target_id=other_subject.node_id,
            relation="candidate_affects",
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=other_evidence,
        )
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.update(
            {
                "future_subject_binding_count": "2",
                "future_subject_binding_ambiguous": "0",
                "future_subject_binding_missing": "1",
            }
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=self.bound.nodes + (other_change, other_subject),
            facts=self.bound.facts + (other_status, other_count),
            relationships=self.bound.relationships + (verified_candidate,),
            metadata=tuple(sorted(forged_metadata.items())),
        )
        forged.validate()

        with self.assertRaisesRegex(ValueError, "remain inferred"):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_rejects_ineligible_candidate_on_other_change(self):
        sibling_signal_id = "signal:other"
        sibling_attributes = dict(self.change_node.attributes)
        sibling_attributes["signal_id"] = sibling_signal_id
        other_change = dataclasses.replace(
            self.change_node,
            node_id=_stable_id(
                "change", self.changeset.changeset_id, sibling_signal_id
            ),
            attributes=tuple(sorted(sibling_attributes.items())),
        )
        ineligible_subject = TwinNode(
            "finding-other",
            TwinNodeKind.FINDING,
            "Ineligible sibling candidate",
        )
        other_evidence = self.signal_evidence_refs
        other_candidate = TwinRelationship(
            relationship_id=_stable_id(
                "relationship",
                other_change.node_id,
                ineligible_subject.node_id,
                "candidate_affects",
            ),
            source_id=other_change.node_id,
            target_id=ineligible_subject.node_id,
            relation="candidate_affects",
            provenance=FactProvenance.INFERRED,
            confidence=0.75,
            evidence_refs=other_evidence,
        )
        other_status = dataclasses.replace(
            self.binding_status,
            fact_id=_stable_id(
                "fact", other_change.node_id, "change.binding_status"
            ),
            subject_id=other_change.node_id,
            evidence_refs=other_evidence,
        )
        other_count = dataclasses.replace(
            self.binding_count,
            fact_id=_stable_id(
                "fact", other_change.node_id, "change.candidate_count"
            ),
            subject_id=other_change.node_id,
            evidence_refs=other_evidence,
        )
        other_signal_facts = tuple(
            dataclasses.replace(
                fact,
                fact_id=_stable_id(
                    "fact", other_change.node_id, fact.predicate, fact.value
                ),
                subject_id=other_change.node_id,
                evidence_refs=other_evidence,
            )
            for fact in self.future.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate in {
                "change.signal_kind",
                "change.direction",
                "change.summary",
            }
        )
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.update(
            {
                "future_subject_binding_count": "2",
                "future_subject_binding_ambiguous": "0",
                "future_subject_binding_missing": "0",
            }
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=self.bound.nodes + (other_change, ineligible_subject),
            facts=self.bound.facts + other_signal_facts + (other_status, other_count),
            relationships=self.bound.relationships + (other_candidate,),
            metadata=tuple(sorted(forged_metadata.items())),
        )
        forged.validate()

        with self.assertRaisesRegex(ValueError, "ineligible subject kind"):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_requires_candidate_binding_metadata(self):
        required_keys = (
            "future_subject_binding",
            "future_subject_binding_count",
            "future_subject_binding_ambiguous",
            "future_subject_binding_missing",
        )
        for key in required_keys:
            with self.subTest(key=key):
                forged_metadata = dict(self.bound.metadata)
                forged_metadata.pop(key)
                forged = dataclasses.replace(
                    self.bound,
                    metadata=tuple(sorted(forged_metadata.items())),
                )
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_subject_resolution_requires_binding_summary_to_match_inferred_state(self):
        for key, forged_value in (
            ("future_subject_binding_count", "2"),
            ("future_subject_binding_ambiguous", "1"),
            ("future_subject_binding_missing", "1"),
            ("future_subject_binding_count", "-1"),
            ("future_subject_binding_count", "not-a-number"),
        ):
            with self.subTest(key=key, forged_value=forged_value):
                forged_metadata = dict(self.bound.metadata)
                forged_metadata[key] = forged_value
                forged = dataclasses.replace(
                    self.bound,
                    metadata=tuple(sorted(forged_metadata.items())),
                )
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_cross_tenant_resolution_fails_closed(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, client_id="client-2"),
                self.state,
            )

    def test_changeset_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, changeset_id="other"),
                self.state,
            )

    def test_ineligible_subject_kind_fails_closed(self):
        finding = TwinNode("finding-1", TwinNodeKind.FINDING, "Finding")
        future = self.future.next_snapshot(
            nodes=self.future.nodes + (finding,),
            relationships=self.future.relationships
            + (
                TwinRelationship(
                    relationship_id="candidate-finding",
                    source_id=self.change_node.node_id,
                    target_id=finding.node_id,
                    relation="candidate_affects",
                    provenance=FactProvenance.INFERRED,
                    confidence=0.5,
                ),
            ),
        )
        resolution = dataclasses.replace(
            self.resolution,
            subject_node_id=finding.node_id,
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(future, resolution, self.state)

    def test_verified_candidate_link_cannot_substitute_for_inferred_binding(self):
        verified_candidate = dataclasses.replace(
            self.candidate,
            relationship_id="candidate-verified",
            provenance=FactProvenance.VERIFIED,
            evidence_refs=("evidence:verified-candidate",),
        )
        future = self.future.next_snapshot(
            relationships=self.future.relationships + (verified_candidate,)
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(future, self.resolution, self.state)

    def test_invalid_evidence_and_missing_operator_rationale_fail_closed(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, evidence_ids=("",)),
                self.state,
            )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, rationale=""),
                self.state,
            )

    def test_invalid_basis_fails_closed(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, basis="model_guess"),
                self.state,
            )

    def test_ambiguous_inferred_candidates_cannot_be_resolved(self):
        other = TwinNode(
            "api-2",
            TwinNodeKind.API,
            "Other API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        ambiguous = self.bound.next_snapshot(
            nodes=self.bound.nodes + (other,),
            relationships=self.bound.relationships
            + (
                TwinRelationship(
                    relationship_id="candidate-2",
                    source_id=self.change_node.node_id,
                    target_id=other.node_id,
                    relation="candidate_affects",
                    provenance=FactProvenance.INFERRED,
                    confidence=0.5,
                    evidence_refs=("evidence:change-signal-1",),
                ),
            ),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(ambiguous, self.resolution, self.state)

    def test_oversized_operator_rationale_fails_closed(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, rationale="x" * 2049),
                self.state,
            )

    def test_subject_resolution_evidence_must_exist(self):
        missing = dataclasses.replace(
            self.resolution,
            evidence_ids=("missing-evidence",),
        )
        with self.assertRaises(KeyError):
            apply_future_subject_resolution(self.bound, missing, self.state)

    def test_subject_resolution_evidence_metadata_must_match_subject(self):
        wrong_evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"wrong subject review",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": self.bound.twin_id,
                "future_twin_version": str(self.bound.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": self.change_node.node_id,
                "subject_node_id": "api-other",
                "candidate_evidence_sha256": self.candidate_evidence_sha256,
                "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
                "rationale_sha256": hashlib.sha256(
                    self.rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        mismatched = dataclasses.replace(
            self.resolution,
            evidence_ids=(wrong_evidence,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.bound, mismatched, self.state)

    def test_subject_resolution_evidence_rejects_extra_metadata_keys(self):
        metadata = {
            "purpose": "future_subject_resolution",
            "decision_id": "decision-1",
            "client_id": "client-1",
            "future_twin_id": self.bound.twin_id,
            "future_twin_version": str(self.bound.version),
            "changeset_id": self.changeset.changeset_id,
            "change_node_id": self.change_node.node_id,
            "subject_node_id": self.subject.node_id,
            "candidate_evidence_sha256": self.candidate_evidence_sha256,
            "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
            "rationale_sha256": hashlib.sha256(
                self.rationale.encode("utf-8")
            ).hexdigest(),
            "untrusted_hint": "api-other",
        }
        evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"review receipt with extra metadata",
            metadata=metadata,
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, evidence_ids=(evidence,)),
                self.state,
            )

    def test_subject_resolution_rejects_duplicate_change_attribute_keys(self):
        forged_change = dataclasses.replace(
            self.change_node,
            attributes=self.change_node.attributes + (("changeset_id", "forged-change"),),
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=tuple(
                forged_change if node.node_id == self.change_node.node_id else node
                for node in self.bound.nodes
            ),
        )
        forged.validate()

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_first_resolution_rejects_duplicate_metadata_keys(self):
        forged = dataclasses.replace(
            self.bound,
            metadata=self.bound.metadata
            + (
                ("future_semantics", "unresolved"),
                ("future_semantics", "resolved"),
            ),
        )
        forged.validate()

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_first_resolution_requires_explicit_future_semantics(self):
        forged_metadata = dict(self.bound.metadata)
        forged_metadata.pop("future_semantics", None)
        forged = dataclasses.replace(
            self.bound,
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_first_resolution_rejects_premature_resolution_marker(self):
        forged_metadata = dict(self.bound.metadata)
        forged_metadata["future_subject_resolution"] = "evidence_recorded"
        forged = dataclasses.replace(
            self.bound,
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_first_resolution_requires_unresolved_future_semantics(self):
        forged_metadata = dict(self.bound.metadata)
        forged_metadata["future_semantics"] = "resolved"
        forged = dataclasses.replace(
            self.bound,
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_first_resolution_requires_twin_changeset_metadata(self):
        for forged_changeset_id in (None, "other-changeset"):
            with self.subTest(forged_changeset_id=forged_changeset_id):
                forged_metadata = dict(self.bound.metadata)
                if forged_changeset_id is None:
                    forged_metadata.pop("changeset_id", None)
                else:
                    forged_metadata["changeset_id"] = forged_changeset_id
                forged = dataclasses.replace(
                    self.bound,
                    metadata=tuple(sorted(forged_metadata.items())),
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_first_resolution_requires_canonical_resolution_count(self):
        for forged_count in ("not-a-number", "-1", "1"):
            with self.subTest(forged_count=forged_count):
                forged_metadata = dict(self.bound.metadata)
                forged_metadata["future_subject_resolution_count"] = forged_count
                forged = dataclasses.replace(
                    self.bound,
                    metadata=tuple(sorted(forged_metadata.items())),
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_subject_resolution_evidence_must_match_declared_run(self):
        other_run = self.state.create_run("other-review", activation_mode="plan_only")
        wrong_run_evidence = self.state.add_evidence(
            other_run,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"same subject but different run",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": self.bound.twin_id,
                "future_twin_version": str(self.bound.version),
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
        mismatched = dataclasses.replace(
            self.resolution,
            evidence_ids=(wrong_run_evidence,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.bound, mismatched, self.state)

    def test_subject_resolution_evidence_contract_is_bounded(self):
        too_many = dataclasses.replace(
            self.resolution,
            evidence_ids=tuple(f"evidence-{index}" for index in range(17)),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.bound, too_many, self.state)

        oversized = dataclasses.replace(
            self.resolution,
            evidence_ids=("x" * 257,),
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.bound, oversized, self.state)

    def test_subject_resolution_evidence_envelope_must_match_basis(self):
        base_metadata = {
            "purpose": "future_subject_resolution",
            "decision_id": "decision-1",
            "client_id": "client-1",
            "future_twin_id": self.bound.twin_id,
            "future_twin_version": str(self.bound.version),
            "changeset_id": self.changeset.changeset_id,
            "change_node_id": self.change_node.node_id,
            "subject_node_id": self.subject.node_id,
            "candidate_evidence_sha256": self.candidate_evidence_sha256,
            "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
            "rationale_sha256": hashlib.sha256(
                self.rationale.encode("utf-8")
            ).hexdigest(),
        }
        wrong_capability = self.state.add_evidence(
            self.run_id,
            "unrelated-capability",
            "operator-review",
            "operator",
            b"wrong capability",
            metadata=base_metadata,
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(
                    self.resolution,
                    evidence_ids=(wrong_capability,),
                ),
                self.state,
            )

        wrong_kind = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "model-output",
            "operator",
            b"wrong evidence kind",
            metadata=base_metadata,
        )
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(
                    self.resolution,
                    evidence_ids=(wrong_kind,),
                ),
                self.state,
            )

    def test_operator_reviewed_evidence_requires_operator_source(self):
        metadata = {
            "purpose": "future_subject_resolution",
            "decision_id": "decision-1",
            "client_id": "client-1",
            "future_twin_id": self.bound.twin_id,
            "future_twin_version": str(self.bound.version),
            "changeset_id": self.changeset.changeset_id,
            "change_node_id": self.change_node.node_id,
            "subject_node_id": self.subject.node_id,
            "candidate_evidence_sha256": self.candidate_evidence_sha256,
            "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
            "rationale_sha256": hashlib.sha256(
                self.rationale.encode("utf-8")
            ).hexdigest(),
        }
        evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "model",
            b"review receipt with wrong source",
            metadata=metadata,
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, evidence_ids=(evidence,)),
                self.state,
            )

    def test_subject_resolution_rejects_noncanonical_evidence_digest(self):
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("not-a-canonical-sha256", self.evidence_id),
            )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_evidence_must_bind_decision_id(self):
        evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"missing decision binding",
            metadata={
                "purpose": "future_subject_resolution",
                "client_id": "client-1",
                "future_twin_id": self.bound.twin_id,
                "future_twin_version": str(self.bound.version),
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
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, evidence_ids=(evidence,)),
                self.state,
            )

    def test_subject_resolution_evidence_is_bound_to_exact_future_snapshot(self):
        later_snapshot = self.bound.next_snapshot()
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                later_snapshot,
                self.resolution,
                self.state,
            )

        sibling_snapshot = dataclasses.replace(
            self.bound,
            twin_id="sibling-future-twin",
        )
        sibling_snapshot.validate()
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                sibling_snapshot,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_evidence_order_is_canonical(self):
        second_evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"second subject review receipt",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": self.bound.twin_id,
                "future_twin_version": str(self.bound.version),
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
        ordered = dataclasses.replace(
            self.resolution,
            evidence_ids=(self.evidence_id, second_evidence),
        )
        once = apply_future_subject_resolution(self.bound, ordered, self.state)
        reordered = dataclasses.replace(
            ordered,
            evidence_ids=(second_evidence, self.evidence_id),
        )
        twice = apply_future_subject_resolution(once, reordered, self.state)
        self.assertIs(twice, once)

    def test_second_decision_for_same_change_fails_closed(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        second_rationale = "Independent review confirms the same subject."
        second_evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"second decision for same change",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-2",
                "client_id": "client-1",
                "future_twin_id": once.twin_id,
                "future_twin_version": str(once.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": self.change_node.node_id,
                "subject_node_id": self.subject.node_id,
                "candidate_evidence_sha256": self.candidate_evidence_sha256,
                "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
                "rationale_sha256": hashlib.sha256(
                    second_rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        second = dataclasses.replace(
            self.resolution,
            decision_id="decision-2",
            evidence_ids=(second_evidence,),
            rationale=second_rationale,
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(once, second, self.state)

    def test_same_resolution_is_idempotent(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        twice = apply_future_subject_resolution(once, self.resolution, self.state)
        self.assertIs(twice, once)

    def test_idempotent_replay_uses_original_input_snapshot_binding(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        twice = apply_future_subject_resolution(once, self.resolution, self.state)
        self.assertIs(twice, once)

        later = once.next_snapshot()
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(later, self.resolution, self.state)

    def test_idempotent_replay_requires_resolution_metadata(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        forged = dataclasses.replace(once, metadata=())

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_idempotent_replay_requires_canonical_parent_lineage(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        forged = dataclasses.replace(
            once,
            parent_twin_id="other-twin",
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_idempotent_replay_rejects_duplicate_metadata_keys(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        forged = dataclasses.replace(
            once,
            metadata=once.metadata + (("future_semantics", "resolved"),),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_idempotent_replay_requires_unresolved_future_semantics(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        forged_metadata = dict(once.metadata)
        forged_metadata["future_semantics"] = "resolved"
        forged = dataclasses.replace(
            once,
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_idempotent_replay_requires_canonical_resolution_count(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        forged_metadata = dict(once.metadata)
        forged_metadata["future_subject_resolution_count"] = "2"
        forged = dataclasses.replace(
            once,
            metadata=tuple(sorted(forged_metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, self.resolution, self.state)

    def test_idempotent_replay_still_requires_ledger_evidence(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        with tempfile.TemporaryDirectory() as tmp:
            empty_state = StateStore(Path(tmp) / "empty-state.db")
            with self.assertRaises(KeyError):
                apply_future_subject_resolution(
                    once,
                    self.resolution,
                    empty_state,
                )

    def test_same_decision_id_with_changed_rationale_fails_closed(self):
        once = apply_future_subject_resolution(self.bound, self.resolution, self.state)
        conflicting = dataclasses.replace(
            self.resolution,
            rationale="A different reviewed ownership rationale.",
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(once, conflicting, self.state)

    def test_same_decision_id_with_conflicting_subject_fails_closed(self):
        once = apply_future_subject_resolution(
            self.bound,
            self.resolution,
            self.state,
        )
        other = TwinNode(
            "api-2",
            TwinNodeKind.API,
            "Other API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        candidate_other = TwinRelationship(
            relationship_id="candidate-2",
            source_id=self.change_node.node_id,
            target_id=other.node_id,
            relation="candidate_affects",
            provenance=FactProvenance.INFERRED,
            confidence=0.75,
            evidence_refs=("evidence:change-signal-1",),
        )
        conflict_base = once.next_snapshot(
            nodes=once.nodes + (other,),
            relationships=tuple(
                item
                for item in once.relationships
                if item.relation != "candidate_affects"
            )
            + (candidate_other,),
        )
        conflict_rationale = "Reviewed mapping now points at api-2."
        conflict_evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"subject api-2 reviewed for change",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": conflict_base.twin_id,
                "future_twin_version": str(conflict_base.version),
                "changeset_id": self.changeset.changeset_id,
                "change_node_id": self.change_node.node_id,
                "subject_node_id": other.node_id,
                "candidate_evidence_sha256": self.candidate_evidence_sha256,
                "resolution_basis": SubjectResolutionBasis.OPERATOR_REVIEWED.value,
                "rationale_sha256": hashlib.sha256(
                    conflict_rationale.encode("utf-8")
                ).hexdigest(),
            },
        )
        conflicting = dataclasses.replace(
            self.resolution,
            subject_node_id=other.node_id,
            evidence_ids=(conflict_evidence,),
            rationale=conflict_rationale,
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                conflict_base,
                conflicting,
                self.state,
            )

    def test_subject_resolution_binds_exact_candidate_evidence_lineage(self):
        stale_candidate = dataclasses.replace(
            self.candidate,
            evidence_refs=("evidence:new-change-signal",),
        )
        stale_status = dataclasses.replace(
            self.binding_status,
            evidence_refs=stale_candidate.evidence_refs,
        )
        stale_count = dataclasses.replace(
            self.binding_count,
            evidence_refs=stale_candidate.evidence_refs,
        )
        rebound = self.future.next_snapshot(
            facts=self.future.facts + (stale_status, stale_count),
            relationships=self.future.relationships + (stale_candidate,),
        )

        rebound_evidence = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"review predates candidate evidence replacement",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": rebound.twin_id,
                "future_twin_version": str(rebound.version),
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
        stale_resolution = dataclasses.replace(
            self.resolution,
            evidence_ids=(rebound_evidence,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(rebound, stale_resolution, self.state)

    def test_partial_verified_subject_state_cannot_be_extended(self):
        forged_fact = TwinFact(
            fact_id="forged-future-subject-node",
            subject_id=self.change_node.node_id,
            predicate="future_subject.node_id",
            value=self.subject.node_id,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=("evidence:forged-subject-state",),
        )
        forged = self.bound.next_snapshot(
            facts=self.bound.facts + (forged_fact,),
        )
        evidence_id = self.state.add_evidence(
            self.run_id,
            "future-subject-resolution",
            "operator-review",
            "operator",
            b"canonical review must not extend partial verified subject state",
            metadata={
                "purpose": "future_subject_resolution",
                "decision_id": "decision-1",
                "client_id": "client-1",
                "future_twin_id": forged.twin_id,
                "future_twin_version": str(forged.version),
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
        resolution = dataclasses.replace(
            self.resolution,
            evidence_ids=(evidence_id,),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(forged, resolution, self.state)

    def test_binding_metadata_counts_must_be_canonical_decimals(self):
        cases = (
            ("future_subject_binding_count", "01"),
            ("future_subject_binding_ambiguous", "+0"),
            ("future_subject_binding_missing", " 0"),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                metadata = dict(self.bound.metadata)
                metadata[key] = value
                forged = dataclasses.replace(
                    self.bound,
                    metadata=tuple(sorted(metadata.items())),
                )
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_resolution_count_metadata_must_be_canonical_decimal(self):
        metadata = dict(self.bound.metadata)
        metadata["future_subject_resolution_count"] = "00"
        forged = dataclasses.replace(
            self.bound,
            metadata=tuple(sorted(metadata.items())),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_subject_resolution_identifiers_must_be_canonical_and_bounded(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, decision_id=" decision-1 "),
                self.state,
            )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, run_id="run\nwith-control"),
                self.state,
            )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(self.resolution, subject_node_id="s" * 257),
                self.state,
            )

    def test_subject_resolution_evidence_ids_must_be_canonical(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(
                    self.resolution,
                    evidence_ids=(f" {self.evidence_id}",),
                ),
                self.state,
            )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                self.bound,
                dataclasses.replace(
                    self.resolution,
                    evidence_ids=("evidence\tcontrol",),
                ),
                self.state,
            )

    def test_integration_evidence_source_must_be_canonical(self):
        cases = (
            " integration-system",
            "integration-system ",
            "integration\nsystem",
        )
        for source in cases:
            with self.subTest(source=repr(source)):
                evidence_id = self.state.add_evidence(
                    self.run_id,
                    "future-subject-resolution",
                    "integration-verification",
                    source,
                    b"integration subject verification receipt",
                    metadata={
                        "purpose": "future_subject_resolution",
                        "decision_id": "decision-1",
                        "client_id": "client-1",
                        "future_twin_id": self.bound.twin_id,
                        "future_twin_version": str(self.bound.version),
                        "changeset_id": self.changeset.changeset_id,
                        "change_node_id": self.change_node.node_id,
                        "subject_node_id": self.subject.node_id,
                        "candidate_evidence_sha256": self.candidate_evidence_sha256,
                        "resolution_basis": SubjectResolutionBasis.INTEGRATION_VERIFIED.value,
                        "rationale_sha256": hashlib.sha256(b"").hexdigest(),
                    },
                )
                resolution = dataclasses.replace(
                    self.resolution,
                    basis=SubjectResolutionBasis.INTEGRATION_VERIFIED,
                    evidence_ids=(evidence_id,),
                    rationale="",
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        self.bound,
                        resolution,
                        self.state,
                    )

    def test_subject_resolution_rationale_must_be_canonical(self):
        cases = (
            f" {self.rationale}",
            f"{self.rationale} ",
            f"\t{self.rationale}",
        )
        for rationale in cases:
            with self.subTest(rationale=repr(rationale)):
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        self.bound,
                        dataclasses.replace(
                            self.resolution,
                            rationale=rationale,
                        ),
                        self.state,
                    )

    def test_projected_change_node_identity_and_metadata_must_remain_canonical(self):
        forged_nodes = (
            dataclasses.replace(
                self.change_node,
                node_id="change:" + "0" * 24,
            ),
            dataclasses.replace(
                self.change_node,
                attributes=tuple(
                    ("signal_id", "forged-signal")
                    if key == "signal_id"
                    else (key, value)
                    for key, value in self.change_node.attributes
                ),
            ),
            dataclasses.replace(
                self.change_node,
                attributes=self.change_node.attributes + (("untrusted_hint", "x"),),
            ),
            dataclasses.replace(
                self.change_node,
                attributes=tuple(
                    ("object_path", " openapi.yaml")
                    if key == "object_path"
                    else (key, value)
                    for key, value in self.change_node.attributes
                ),
            ),
        )

        for forged_change in forged_nodes:
            with self.subTest(
                node_id=forged_change.node_id,
                attributes=forged_change.attributes,
            ):
                forged = dataclasses.replace(
                    self.bound,
                    nodes=tuple(
                        forged_change
                        if node.node_id == self.change_node.node_id
                        else node
                        for node in self.bound.nodes
                    ),
                )
                with self.assertRaises((KeyError, ValueError)):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_projected_change_label_must_match_summary_fact(self):
        forged_change = dataclasses.replace(
            self.change_node,
            label="Forged summary label",
        )
        forged = dataclasses.replace(
            self.bound,
            nodes=tuple(
                forged_change if node.node_id == self.change_node.node_id else node
                for node in self.bound.nodes
            ),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_change_signal_fact_ids_and_confidence_must_remain_canonical(self):
        signal_facts = {
            fact.predicate: fact
            for fact in self.bound.facts
            if fact.subject_id == self.change_node.node_id
            and fact.predicate
            in {"change.signal_kind", "change.direction", "change.summary"}
        }
        summary_fact = signal_facts["change.summary"]
        direction_fact = signal_facts["change.direction"]
        bad_confidence = 0.0 if direction_fact.confidence != 0.0 else 1.0
        bad_facts = (
            dataclasses.replace(summary_fact, fact_id="forged-change-signal"),
            dataclasses.replace(direction_fact, confidence=bad_confidence),
        )

        for bad_fact in bad_facts:
            with self.subTest(
                predicate=bad_fact.predicate,
                fact_id=bad_fact.fact_id,
                confidence=bad_fact.confidence,
            ):
                forged = dataclasses.replace(
                    self.bound,
                    facts=tuple(
                        bad_fact if fact.fact_id == (
                            summary_fact.fact_id
                            if bad_fact.predicate == "change.summary"
                            else direction_fact.fact_id
                        ) else fact
                        for fact in self.bound.facts
                    ),
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_candidate_binding_must_remain_attached_to_change_signal_evidence(self):
        forged_refs = ("patch-sha256:" + "f" * 64,)
        forged_status = dataclasses.replace(
            self.binding_status,
            evidence_refs=forged_refs,
        )
        forged_count = dataclasses.replace(
            self.binding_count,
            evidence_refs=forged_refs,
        )
        forged_candidate = dataclasses.replace(
            self.candidate,
            evidence_refs=forged_refs,
        )
        forged = dataclasses.replace(
            self.bound,
            facts=tuple(
                forged_status
                if fact.fact_id == self.binding_status.fact_id
                else forged_count
                if fact.fact_id == self.binding_count.fact_id
                else fact
                for fact in self.bound.facts
            ),
            relationships=tuple(
                forged_candidate
                if relationship.relationship_id == self.candidate.relationship_id
                else relationship
                for relationship in self.bound.relationships
            ),
        )

        with self.assertRaises(ValueError):
            apply_future_subject_resolution(
                forged,
                self.resolution,
                self.state,
            )

    def test_candidate_binding_fact_ids_and_confidence_must_be_canonical(self):
        bad_facts = (
            dataclasses.replace(self.binding_status, fact_id="forged-binding-status"),
            dataclasses.replace(self.binding_count, confidence=0.5),
        )
        for bad_fact in bad_facts:
            with self.subTest(fact_id=bad_fact.fact_id, confidence=bad_fact.confidence):
                forged = dataclasses.replace(
                    self.bound,
                    facts=tuple(
                        bad_fact if fact.fact_id == (
                            self.binding_status.fact_id
                            if bad_fact.predicate == "change.binding_status"
                            else self.binding_count.fact_id
                        ) else fact
                        for fact in self.bound.facts
                    ),
                )
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_candidate_binding_relationship_id_and_confidence_must_be_canonical(self):
        bad_relationships = (
            dataclasses.replace(self.candidate, relationship_id="forged-candidate-link"),
            dataclasses.replace(self.candidate, confidence=1.0),
        )
        for bad_relationship in bad_relationships:
            with self.subTest(
                relationship_id=bad_relationship.relationship_id,
                confidence=bad_relationship.confidence,
            ):
                forged = dataclasses.replace(
                    self.bound,
                    relationships=tuple(
                        bad_relationship
                        if relationship.relationship_id == self.candidate.relationship_id
                        else relationship
                        for relationship in self.bound.relationships
                    ),
                )
                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        self.resolution,
                        self.state,
                    )

    def test_candidate_evidence_lineage_refs_must_be_canonical(self):
        malformed_cases = (
            ("surrounding-whitespace", (" evidence:change-signal-1",)),
            (
                "duplicate-ref",
                ("evidence:change-signal-1", "evidence:change-signal-1"),
            ),
        )
        for label, bad_refs in malformed_cases:
            with self.subTest(label=label):
                forged = dataclasses.replace(
                    self.bound,
                    facts=tuple(
                        dataclasses.replace(fact, evidence_refs=bad_refs)
                        if fact.fact_id
                        in {self.binding_status.fact_id, self.binding_count.fact_id}
                        else fact
                        for fact in self.bound.facts
                    ),
                    relationships=tuple(
                        dataclasses.replace(relationship, evidence_refs=bad_refs)
                        if relationship.relationship_id
                        == self.candidate.relationship_id
                        else relationship
                        for relationship in self.bound.relationships
                    ),
                )
                candidate_digest = hashlib.sha256(
                    "\x1f".join(sorted(bad_refs)).encode("utf-8")
                ).hexdigest()
                evidence_id = self.state.add_evidence(
                    self.run_id,
                    "future-subject-resolution",
                    "operator-review",
                    "operator",
                    f"review receipt for malformed lineage: {label}".encode("utf-8"),
                    metadata={
                        "purpose": "future_subject_resolution",
                        "decision_id": "decision-1",
                        "client_id": "client-1",
                        "future_twin_id": forged.twin_id,
                        "future_twin_version": str(forged.version),
                        "changeset_id": self.changeset.changeset_id,
                        "change_node_id": self.change_node.node_id,
                        "subject_node_id": self.subject.node_id,
                        "candidate_evidence_sha256": candidate_digest,
                        "resolution_basis": (
                            SubjectResolutionBasis.OPERATOR_REVIEWED.value
                        ),
                        "rationale_sha256": hashlib.sha256(
                            self.rationale.encode("utf-8")
                        ).hexdigest(),
                    },
                )
                resolution = dataclasses.replace(
                    self.resolution,
                    evidence_ids=(evidence_id,),
                )

                with self.assertRaises(ValueError):
                    apply_future_subject_resolution(
                        forged,
                        resolution,
                        self.state,
                    )

    def test_current_twin_cannot_accept_future_subject_resolution(self):
        with self.assertRaises(ValueError):
            apply_future_subject_resolution(self.current, self.resolution, self.state)


if __name__ == "__main__":
    unittest.main()
