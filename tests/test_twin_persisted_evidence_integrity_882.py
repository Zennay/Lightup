"""Independent real-SQLite Security Twin evidence-integrity acceptance (#882).

All data is synthetic and local. This branch does not modify the finding
reader or twin production code. RED tests intentionally document unresolved
source-owner invariants; an expected failure is NOT a security pass.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity
from lightup.twin import FactProvenance, TwinNodeKind
from lightup.twin_projection import project_current_twin


class TwinPersistedEvidenceIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "synthetic-twin.db"
        self.store = DomainStore(self.db_path)
        self.operator = AccessContext("operator-synthetic", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Twin evidence lab A")
        self.other_client = self.store.create_client(self.operator, "Twin evidence lab B")
        self.ctx = AccessContext("synthetic-client-a", Role.CLIENT_ADMIN, self.client.client_id)
        self.other_ctx = AccessContext(
            "synthetic-client-b", Role.CLIENT_ADMIN, self.other_client.client_id
        )
        engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Offline evidence lab"
        )
        self.finding = self.store.record_finding(
            self.operator,
            engagement.engagement_id,
            "Synthetic HSTS finding",
            Severity.MEDIUM,
            "asset://synthetic",
            "Synthetic impact",
            "Synthetic remediation",
            evidence_ids=("evidence:two", "evidence:one"),
        )
        other_engagement = self.store.create_engagement(
            self.operator, self.other_client.client_id, "Independent tenant"
        )
        self.other_finding = self.store.record_finding(
            self.operator,
            other_engagement.engagement_id,
            "Other synthetic finding",
            Severity.LOW,
            "asset://other",
            "Other synthetic impact",
            "Other synthetic remediation",
            evidence_ids=("other:evidence",),
        )

    def _raw(self) -> str:
        # Reopen the real on-disk database independently of DomainStore caches.
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    def _corrupt(self, raw: str) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )
        self.assertEqual(self._raw(), raw)

    def _project(self):
        return project_current_twin(self.store, self.ctx)

    def _reject_atomically(self, raw: str) -> None:
        self._corrupt(raw)
        before = self._raw()
        with self.assertRaisesRegex(ValueError, "[Ee]vidence"):
            self._project()
        self.assertEqual(self._raw(), before)

    def test_canonical_evidence_produces_verified_path_without_losing_refs(self) -> None:
        twin = self._project()
        twin.validate()
        matching_nodes = [
            node for node in twin.nodes
            if node.kind is TwinNodeKind.FINDING
        ]
        self.assertEqual(len(matching_nodes), 1)
        self.assertEqual(matching_nodes[0].node_id, f"finding:{self.finding.finding_id}")
        self.assertEqual(len(twin.attack_paths), 1)
        path = twin.attack_paths[0]
        self.assertEqual(path.path_id, f"path:{self.finding.finding_id}")
        self.assertEqual(path.evidence_refs, ("evidence:one", "evidence:two"))
        self.assertEqual(path.steps[0].evidence_refs, path.evidence_refs)
        verified_facts = [
            fact for fact in twin.facts
            if fact.provenance is FactProvenance.VERIFIED
        ]
        self.assertEqual(len(verified_facts), 1)
        self.assertEqual(verified_facts[0].evidence_refs, path.evidence_refs)
        verified_relations = [
            rel for rel in twin.relationships
            if rel.provenance is FactProvenance.VERIFIED
        ]
        self.assertEqual(len(verified_relations), 1)
        self.assertEqual(verified_relations[0].evidence_refs, path.evidence_refs)

    def test_independent_tenant_projects_only_its_own_evidence(self) -> None:
        self._corrupt('{"evidence:one": true}')
        twin = project_current_twin(self.store, self.other_ctx)
        self.assertEqual(len(twin.attack_paths), 1)
        self.assertEqual(twin.attack_paths[0].path_id, f"path:{self.other_finding.finding_id}")
        self.assertEqual(twin.attack_paths[0].evidence_refs, ("other:evidence",))
        self.assertEqual(self._raw(), '{"evidence:one": true}')

    @unittest.expectedFailure  # RED until #856 fixes the shared durable decoder
    def test_string_is_not_interpreted_as_character_evidence(self) -> None:
        self._reject_atomically('"evidence:one"')

    @unittest.expectedFailure  # RED until #856 fixes the shared durable decoder
    def test_object_keys_are_not_promoted_to_verified_lineage(self) -> None:
        self._reject_atomically('{"evidence:one": true}')

    @unittest.expectedFailure  # RED until #856 fixes the shared durable decoder
    def test_mixed_scalar_array_fails_before_verified_projection(self) -> None:
        self._reject_atomically('["evidence:one", 7]')

    @unittest.expectedFailure  # RED until #856 fixes the shared durable decoder
    def test_blank_evidence_is_not_silently_omitted(self) -> None:
        self._reject_atomically('["   "]')

    @unittest.expectedFailure  # RED until #856 fixes the shared durable decoder
    def test_duplicate_evidence_is_not_silently_deduplicated(self) -> None:
        self._reject_atomically('["evidence:one", "evidence:one"]')


if __name__ == "__main__":
    unittest.main()
