from __future__ import annotations

import copy
import unittest
from unittest import mock

import test_future_security_evidence_sufficiency_verifier_preflight_consumer as consumer_tests
from lightup.domain import AccessContext, Role


class FutureSecurityEvidenceSufficiencyVerifierPreflightConsumerReadonlyTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceSufficiencyVerifierPreflightConsumerTest(
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
        self.assertEqual(produced[1:14], before)

    def _consume_with_write_sentinels(
        self,
        persisted: object,
        produced: tuple,
        *,
        verifier=None,
    ):
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
            result = self.base._consume(
                persisted,
                produced,
                verifier=verifier,
            )

        create_run.assert_not_called()
        acquire_lease.assert_not_called()
        add_evidence.assert_not_called()
        return result

    def test_successful_live_consumption_is_read_only(self):
        produced = self.base._producer(
            suffix="verifier-preflight-consumer-readonly-success"
        )
        preflight = produced[-1]
        before_live = copy.deepcopy(produced[1:14])
        before_state = self._state_snapshot()

        first = self._consume_with_write_sentinels(preflight.to_json(), produced)
        self.assertEqual(first, preflight)
        self._assert_live_inputs_unchanged(produced, before_live)
        self.assertEqual(self._state_snapshot(), before_state)

        second = self._consume_with_write_sentinels(preflight.to_json(), produced)
        self.assertEqual(second, preflight)
        self.assertEqual(second, first)
        self._assert_live_inputs_unchanged(produced, before_live)
        self.assertEqual(self._state_snapshot(), before_state)

    def test_live_identity_rejection_is_read_only(self):
        produced = self.base._producer(
            suffix="verifier-preflight-consumer-readonly-rejection"
        )
        preflight = produced[-1]
        different = AccessContext(user_id="operator-different", role=Role.OPERATOR)
        before_live = copy.deepcopy(produced[1:14])
        before_state = self._state_snapshot()

        for _ in range(2):
            with self.assertRaisesRegex(
                ValueError, "does not match live validated lineage"
            ):
                self._consume_with_write_sentinels(
                    preflight.to_json(),
                    produced,
                    verifier=different,
                )
            self._assert_live_inputs_unchanged(produced, before_live)
            self.assertEqual(self._state_snapshot(), before_state)


if __name__ == "__main__":
    unittest.main()
