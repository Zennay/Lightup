from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class PersistedAssessmentRequestAssetIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-request-read", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Request Read Client")
        self.client_ctx = AccessContext(
            "client-request-read",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )

    def _request(self):
        return self.store.submit_assessment_request(
            self.client_ctx,
            ("app.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
        )

    def _replace_assets_json(self, request_id: str, payload: object) -> str:
        encoded = json.dumps(payload)
        with self.store._connect() as con:
            con.execute(
                "UPDATE assessment_requests SET requested_assets_json=? "
                "WHERE request_id=?",
                (encoded, request_id),
            )
        return encoded

    def _stored_assets_json(self, request_id: str) -> str:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT requested_assets_json FROM assessment_requests "
                "WHERE request_id=?",
                (request_id,),
            ).fetchone()
        assert row is not None
        return row["requested_assets_json"]

    def test_canonical_persisted_asset_array_round_trips(self):
        request = self._request()

        persisted = self.store.get_assessment_request(
            self.client_ctx,
            request.request_id,
        )

        self.assertEqual(persisted.requested_assets, ("app.example.test",))

    def test_corrupt_persisted_asset_shapes_fail_closed_without_repair(self):
        corrupt_payloads = (
            {"app.example.test": True},
            "app.example.test",
            ["app.example.test", 7],
            [],
            [" "],
        )

        for payload in corrupt_payloads:
            with self.subTest(payload=payload):
                request = self._request()
                encoded = self._replace_assets_json(request.request_id, payload)

                with self.assertRaises((TypeError, ValueError)):
                    self.store.get_assessment_request(
                        self.client_ctx,
                        request.request_id,
                    )

                self.assertEqual(
                    self._stored_assets_json(request.request_id),
                    encoded,
                )


if __name__ == "__main__":
    unittest.main()
