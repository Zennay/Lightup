from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity
from lightup.twin_projection import project_current_twin


class FindingTwinEvidenceReadIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-finding-twin-evidence", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator,
            "Twin evidence read client",
        )
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Twin evidence read engagement",
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Evidence-backed finding",
            severity=Severity.MEDIUM,
            asset="asset://lab",
            impact="Synthetic impact",
            remediation="Synthetic remediation",
            evidence_ids=("evidence:one", "evidence:two"),
        )

    def _raw_evidence_json(self) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["evidence_ids_json"]

    def _replace_evidence_json(self, raw: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def _project(self):
        return project_current_twin(
            self.store,
            self.operator,
            self.client.client_id,
        )

    def _assert_projection_rejected_without_mutation(self, raw: str) -> None:
        self._replace_evidence_json(raw)
        before = self._raw_evidence_json()

        with self.assertRaisesRegex(ValueError, "evidence"):
            self._project()

        self.assertEqual(self._raw_evidence_json(), before)

    def test_canonical_evidence_projects_to_verified_attack_path(self) -> None:
        twin = self._project()

        path = next(
            path
            for path in twin.attack_paths
            if path.path_id == f"path:{self.finding.finding_id}"
        )
        self.assertEqual(path.evidence_refs, ("evidence:one", "evidence:two"))
        self.assertEqual(
            path.steps[0].evidence_refs,
            ("evidence:one", "evidence:two"),
        )

    def test_persisted_string_cannot_be_repaired_by_projection(self) -> None:
        self._assert_projection_rejected_without_mutation('"evidence:one"')

    def test_persisted_object_cannot_be_repaired_by_projection(self) -> None:
        self._assert_projection_rejected_without_mutation(
            '{"evidence:one": true}'
        )

    def test_mixed_array_cannot_cross_into_verified_twin_lineage(self) -> None:
        self._assert_projection_rejected_without_mutation(
            '["evidence:one", 7]'
        )

    def test_blank_reference_cannot_be_silently_dropped_by_projection(self) -> None:
        self._assert_projection_rejected_without_mutation('["   "]')

    def test_duplicate_references_cannot_be_silently_deduplicated(self) -> None:
        self._assert_projection_rejected_without_mutation(
            '["evidence:duplicate", "evidence:duplicate"]'
        )


if __name__ == "__main__":
    unittest.main()
