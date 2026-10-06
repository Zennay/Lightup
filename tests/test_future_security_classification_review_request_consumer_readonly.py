from __future__ import annotations

import dataclasses
import unittest

import test_future_security_classification_review_request_consumer as consumer_tests
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)


class FutureSecurityClassificationReviewConsumerReadOnlyTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityClassificationReviewRequestConsumerTest(
            "test_real_producer_json_is_parsed_and_live_validated_as_one_boundary"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    @classmethod
    def _snapshot_value(cls, value):
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        if isinstance(value, tuple):
            return tuple(cls._snapshot_value(item) for item in value)
        if isinstance(value, list):
            return tuple(cls._snapshot_value(item) for item in value)
        if isinstance(value, dict):
            return tuple(
                (key, cls._snapshot_value(item))
                for key, item in value.items()
            )
        return value

    @classmethod
    def _lineage_snapshot(cls, produced):
        return tuple(cls._snapshot_value(value) for value in produced)

    def _state_snapshot(self):
        queries = (
            (
                "runs",
                "SELECT run_id,target,authorization_ref,activation_mode,status,created_at "
                "FROM runs ORDER BY run_id",
            ),
            (
                "capability_leases",
                "SELECT run_id,capability_id,worker_id,expires_at "
                "FROM capability_leases ORDER BY run_id,capability_id",
            ),
            (
                "evidence",
                "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                "metadata_json,created_at FROM evidence ORDER BY evidence_id",
            ),
        )
        with self.state.connect() as con:
            return tuple(
                (
                    name,
                    tuple(tuple(row) for row in con.execute(query).fetchall()),
                )
                for name, query in queries
            )

    def test_successful_consumer_validation_is_read_only(self):
        produced = self._producer(suffix="classification-consumer-readonly-success")
        persisted = produced[-1].to_json()
        lineage_before = self._lineage_snapshot(produced)
        state_before = self._state_snapshot()

        consumed = self.base._consume(persisted, produced)

        self.assertEqual(consumed, produced[-1])
        self.assertEqual(self._lineage_snapshot(produced), lineage_before)
        self.assertEqual(self._state_snapshot(), state_before)

    def test_live_lineage_rejection_is_read_only_and_deterministic(self):
        produced = list(
            self._producer(suffix="classification-consumer-readonly-rejection")
        )
        request = produced[-1]
        produced[-2] = dataclasses.replace(
            produced[-2],
            attestation_sha256="0" * 64,
        )
        produced = tuple(produced)
        lineage_before = self._lineage_snapshot(produced)
        state_before = self._state_snapshot()

        messages = []
        for attempt in range(2):
            with self.subTest(attempt=attempt + 1):
                with self.assertRaisesRegex(
                    ValueError,
                    "live validated lineage",
                ) as raised:
                    self.base._consume(request.to_json(), produced)
                messages.append(str(raised.exception))
                self.assertEqual(
                    self._lineage_snapshot(produced),
                    lineage_before,
                )
                self.assertEqual(self._state_snapshot(), state_before)

        self.assertEqual(messages[0], messages[1])


if __name__ == "__main__":
    unittest.main()
