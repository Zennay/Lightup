from __future__ import annotations

import copy
import unittest
from unittest import mock

import test_future_security_evidence_freshness_coverage_consumer as consumer_tests


class FutureSecurityEvidenceFreshnessCoverageConsumerReadonlyTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceFreshnessCoverageConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    def _live_inputs(self, produced: tuple) -> tuple:
        return produced[1:10] + (produced[11],)

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
        produced = self._producer(suffix="coverage-consumer-readonly-success")
        coverage = produced[-1]
        before_live = copy.deepcopy(self._live_inputs(produced))
        before_state = self._state_snapshot()

        first = self._consume_with_write_sentinels(coverage.to_json(), produced)
        self.assertEqual(first, coverage)
        self.assertEqual(self._live_inputs(produced), before_live)
        self.assertEqual(self._state_snapshot(), before_state)

        second = self._consume_with_write_sentinels(coverage.to_json(), produced)
        self.assertEqual(second, coverage)
        self.assertEqual(second, first)
        self.assertEqual(self._live_inputs(produced), before_live)
        self.assertEqual(self._state_snapshot(), before_state)

    def test_live_evidence_rejection_is_read_only(self):
        produced = self._producer(suffix="coverage-consumer-readonly-rejection")
        evidence_id = produced[10]
        coverage = produced[-1]

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        before_live = copy.deepcopy(self._live_inputs(produced))
        before_state = self._state_snapshot()

        for _ in range(2):
            with self.assertRaises(ValueError):
                self._consume_with_write_sentinels(coverage.to_json(), produced)
            self.assertEqual(self._live_inputs(produced), before_live)
            self.assertEqual(self._state_snapshot(), before_state)


if __name__ == "__main__":
    unittest.main()
