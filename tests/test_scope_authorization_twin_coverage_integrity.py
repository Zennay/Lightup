from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.twin import FactProvenance
from lightup.twin_projection import project_current_twin


class TwinCoverageIntegrityAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("operator", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Coverage tenant")
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Coverage projection boundary",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _inject_coverage(self, capability_id: str, status: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "INSERT INTO coverage_entries("
                "engagement_id,capability_id,status,updated_at"
                ") VALUES(?,?,?,?)",
                (
                    self.engagement.engagement_id,
                    capability_id,
                    status,
                    "2026-10-07T00:00:00+00:00",
                ),
            )

    def _durable_coverage(self) -> list[tuple[str, str]]:
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT capability_id,status FROM coverage_entries "
                "WHERE engagement_id=? ORDER BY capability_id",
                (self.engagement.engagement_id,),
            ).fetchall()
        return [(row["capability_id"], row["status"]) for row in rows]

    def test_corrupt_durable_coverage_cannot_enter_current_twin(self) -> None:
        corrupt_cases = (
            ("unknown-capability", "assessed"),
            ("web-baseline", "not-a-status"),
        )

        for capability_id, status in corrupt_cases:
            with self.subTest(capability_id=capability_id, status=status):
                self._inject_coverage(capability_id, status)

                with self.assertRaises(ValueError):
                    project_current_twin(
                        self.store,
                        self.operator,
                        self.client.client_id,
                    )

                self.assertEqual(
                    self._durable_coverage(),
                    [(capability_id, status)],
                )
                with self.store._connect() as con:
                    con.execute(
                        "DELETE FROM coverage_entries WHERE engagement_id=?",
                        (self.engagement.engagement_id,),
                    )

    def test_canonical_coverage_projects_as_observed_fact(self) -> None:
        self.store.set_coverage(
            self.operator,
            self.engagement.engagement_id,
            "web-baseline",
            "assessed",
        )

        twin = project_current_twin(
            self.store,
            self.operator,
            self.client.client_id,
        )

        coverage_facts = [
            fact
            for fact in twin.facts
            if fact.predicate == "coverage:web-baseline"
        ]
        self.assertEqual(len(coverage_facts), 1)
        self.assertEqual(coverage_facts[0].value, "assessed")
        self.assertIs(coverage_facts[0].provenance, FactProvenance.OBSERVED)


if __name__ == "__main__":
    unittest.main()
