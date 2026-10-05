from __future__ import annotations

import unittest

from lightup.twin import (
    AttackPath,
    AttackStep,
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNode,
    TwinNodeKind,
    TwinRelationship,
    TwinSnapshotKind,
)


class SecurityTwinTest(unittest.TestCase):
    def setUp(self):
        self.app = TwinNode("app-1", TwinNodeKind.APPLICATION, "Customer portal")
        self.api = TwinNode("api-1", TwinNodeKind.API, "Billing API")
        self.data = TwinNode("data-1", TwinNodeKind.DATA, "Invoices")

    def test_current_twin_starts_versioned_and_empty(self):
        twin = SecurityTwin.current("client-1")
        twin.validate()
        self.assertEqual(twin.version, 1)
        self.assertIs(twin.kind, TwinSnapshotKind.CURRENT)
        self.assertEqual(twin.client_id, "client-1")
        self.assertEqual(twin.nodes, ())

    def test_verified_fact_requires_evidence(self):
        fact = TwinFact(
            "fact-1",
            "app-1",
            "internet_exposed",
            "true",
            FactProvenance.VERIFIED,
            1.0,
        )
        with self.assertRaises(ValueError):
            fact.validate()

    def test_inferred_fact_may_exist_without_evidence_but_is_not_verified(self):
        fact = TwinFact(
            "fact-1",
            "app-1",
            "may_reach",
            "api-1",
            FactProvenance.INFERRED,
            0.55,
        )
        fact.validate()
        self.assertIs(fact.provenance, FactProvenance.INFERRED)

    def test_snapshot_rejects_facts_for_unknown_nodes(self):
        twin = SecurityTwin.current("client-1")
        fact = TwinFact(
            "fact-1",
            "missing",
            "internet_exposed",
            "true",
            FactProvenance.OBSERVED,
            0.9,
            ("evidence-1",),
        )
        with self.assertRaises(ValueError):
            twin.next_snapshot(facts=(fact,))

    def test_verified_relationship_requires_evidence(self):
        relationship = TwinRelationship(
            "rel-1",
            "app-1",
            "api-1",
            "calls",
            FactProvenance.VERIFIED,
            1.0,
        )
        with self.assertRaises(ValueError):
            relationship.validate()

    def test_next_snapshot_is_immutable_and_increments_version(self):
        current = SecurityTwin.current("client-1")
        updated = current.next_snapshot(nodes=(self.app, self.api))
        self.assertEqual(current.version, 1)
        self.assertEqual(current.nodes, ())
        self.assertEqual(updated.version, 2)
        self.assertEqual(updated.parent_twin_id, current.twin_id)
        self.assertEqual(updated.parent_version, 1)
        self.assertEqual(updated.nodes, (self.app, self.api))

    def test_attack_path_must_be_contiguous(self):
        path = AttackPath(
            "path-1",
            "Broken chain",
            (
                AttackStep("app-1", "api-1", "calls"),
                AttackStep("data-1", "app-1", "returns"),
            ),
        )
        with self.assertRaises(ValueError):
            path.validate()

    def test_snapshot_accepts_evidence_backed_attack_path(self):
        relationship = TwinRelationship(
            "rel-1",
            "app-1",
            "api-1",
            "calls",
            FactProvenance.VERIFIED,
            1.0,
            ("evidence-call",),
        )
        path = AttackPath(
            "path-1",
            "Portal can reach billing API",
            (AttackStep("app-1", "api-1", "calls", ("evidence-call",)),),
            ("evidence-call",),
        )
        twin = SecurityTwin.current("client-1").next_snapshot(
            nodes=(self.app, self.api),
            relationships=(relationship,),
            attack_paths=(path,),
        )
        twin.validate()
        self.assertEqual(twin.attack_paths[0].path_id, "path-1")

    def test_stable_digest_is_deterministic_and_binds_snapshot_content(self):
        current = SecurityTwin.current("client-1").next_snapshot(
            nodes=(self.app, self.api)
        )
        same_digest = current.stable_digest()
        self.assertEqual(current.stable_digest(), same_digest)

        changed = current.next_snapshot(
            nodes=(self.app, self.api, self.data)
        )
        self.assertNotEqual(changed.stable_digest(), same_digest)

    def test_future_twin_is_a_separate_branch_with_source_reference(self):
        current = SecurityTwin.current("client-1").next_snapshot(
            nodes=(self.app, self.api, self.data)
        )
        future = current.derive_future("github:Zennay/Lightup#123")
        self.assertIs(future.kind, TwinSnapshotKind.FUTURE)
        self.assertNotEqual(future.twin_id, current.twin_id)
        self.assertEqual(future.parent_twin_id, current.twin_id)
        self.assertEqual(future.parent_version, current.version)
        self.assertEqual(future.source_ref, "github:Zennay/Lightup#123")
        self.assertEqual(current.kind, TwinSnapshotKind.CURRENT)

    def test_future_twin_cannot_exist_without_source_reference(self):
        twin = SecurityTwin(
            twin_id="future-1",
            client_id="client-1",
            version=1,
            kind=TwinSnapshotKind.FUTURE,
        )
        with self.assertRaises(ValueError):
            twin.validate()


if __name__ == "__main__":
    unittest.main()
