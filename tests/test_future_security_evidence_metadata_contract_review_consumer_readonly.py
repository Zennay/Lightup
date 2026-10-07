from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

import test_future_security_evidence_metadata_contract_review_consumer as consumer_tests


class FutureSecurityEvidenceMetadataContractReviewConsumerReadonlyTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceMetadataContractReviewConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.state = self.base.state

    def _state_snapshot(self):
        with self.state.connect() as con:
            return {
                table: tuple(
                    tuple(row)
                    for row in con.execute(
                        f"SELECT * FROM {table} ORDER BY rowid"
                    ).fetchall()
                )
                for table in ("runs", "capability_leases", "evidence")
            }

    def _assert_live_inputs_unchanged(self, produced: tuple, before: tuple) -> None:
        self.assertEqual(produced[1:11], before)

    def _consume_with_write_sentinels(self, persisted: object, produced: tuple):
        with (
            mock.patch.object(
                self.state,
                "create_run",
                side_effect=AssertionError("consumer must not create runs"),
            ) as create_run,
            mock.patch.object(
                self.state,
                "acquire_lease",
                side_effect=AssertionError("consumer must not acquire capability leases"),
            ) as acquire_lease,
            mock.patch.object(
                self.state,
                "add_evidence",
                side_effect=AssertionError("consumer must not add evidence"),
            ) as add_evidence,
        ):
            result = self.base._consume(persisted, produced)

        create_run.assert_not_called()
        acquire_lease.assert_not_called()
        add_evidence.assert_not_called()
        return result

    def test_successful_live_consumption_is_read_only(self):
        produced = self.base._producer(suffix="metadata-review-consumer-readonly-success")
        review = produced[-1]
        before_live = copy.deepcopy(produced[1:11])
        before_state = self._state_snapshot()

        first = self._consume_with_write_sentinels(review.to_json(), produced)
        self.assertEqual(first, review)
        self._assert_live_inputs_unchanged(produced, before_live)
        self.assertEqual(self._state_snapshot(), before_state)

        second = self._consume_with_write_sentinels(review.to_json(), produced)
        self.assertEqual(second, review)
        self.assertEqual(second, first)
        self._assert_live_inputs_unchanged(produced, before_live)
        self.assertEqual(self._state_snapshot(), before_state)

    def test_live_metadata_rejection_is_read_only(self):
        produced = self.base._producer(
            suffix="metadata-review-consumer-readonly-rejection"
        )
        admission = produced[10]
        review = produced[-1]
        evidence_id = admission.candidate_evidence_ids[0]
        record = self.state.get_evidence(evidence_id)
        metadata = dict(record.metadata)
        metadata["proposal_sha256"] = "0" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                (
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                    evidence_id,
                ),
            )

        before_live = copy.deepcopy(produced[1:11])
        before_state = self._state_snapshot()

        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "metadata contract mismatch"):
                self._consume_with_write_sentinels(review.to_json(), produced)
            self._assert_live_inputs_unchanged(produced, before_live)
            self.assertEqual(self._state_snapshot(), before_state)


if __name__ == "__main__":
    unittest.main()
