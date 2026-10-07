from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class AssessmentRequesterProvenanceReadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Requester provenance client")
        self.ctx = AccessContext("user-a", Role.CLIENT_ADMIN, self.client.client_id)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _request(self):
        return self.store.submit_assessment_request(
            self.ctx,
            ("app.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )

    def _persisted_requested_by(self, request_id: str):
        with self.store._connect() as con:
            return con.execute(
                "SELECT requested_by FROM assessment_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()["requested_by"]

    def test_canonical_requested_by_round_trips(self) -> None:
        request = self._request()

        loaded = self.store.get_assessment_request(self.ctx, request.request_id)

        self.assertEqual(loaded.requested_by, "user-a")
        self.assertIs(type(loaded.requested_by), str)

    def test_blob_requested_by_fails_closed_without_repair(self) -> None:
        request = self._request()
        corrupt = sqlite3.Binary(b"user-a")
        with self.store._connect() as con:
            con.execute(
                "UPDATE assessment_requests SET requested_by=? WHERE request_id=?",
                (corrupt, request.request_id),
            )

        with self.assertRaises(ValueError):
            self.store.get_assessment_request(self.operator, request.request_id)

        persisted = self._persisted_requested_by(request.request_id)
        self.assertEqual(persisted, b"user-a")
        self.assertIs(type(persisted), bytes)

    def test_blank_requested_by_fails_closed_without_repair(self) -> None:
        request = self._request()
        for corrupt in ("", "   "):
            with self.subTest(corrupt=repr(corrupt)):
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE assessment_requests SET requested_by=? WHERE request_id=?",
                        (corrupt, request.request_id),
                    )

                with self.assertRaises(ValueError):
                    self.store.get_assessment_request(self.operator, request.request_id)

                self.assertEqual(self._persisted_requested_by(request.request_id), corrupt)


if __name__ == "__main__":
    unittest.main()
