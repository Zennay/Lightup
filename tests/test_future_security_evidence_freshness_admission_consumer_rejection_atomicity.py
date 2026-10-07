from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness_admission_consumer as consumer_tests


def _container_identities(value: object, path: tuple[object, ...] = ()) -> dict[tuple[object, ...], int]:
    identities: dict[tuple[object, ...], int] = {}
    if isinstance(value, dict):
        identities[path] = id(value)
        for key, nested in value.items():
            identities.update(_container_identities(nested, path + (key,)))
    elif isinstance(value, list):
        identities[path] = id(value)
        for index, nested in enumerate(value):
            identities.update(_container_identities(nested, path + (index,)))
    return identities


def _ordered_shape(value: object):
    if isinstance(value, dict):
        return ("dict", tuple((key, _ordered_shape(nested)) for key, nested in value.items()))
    if isinstance(value, list):
        return ("list", tuple(_ordered_shape(nested) for nested in value))
    return ("value", value)


class FutureSecurityEvidenceFreshnessAdmissionConsumerRejectionAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceFreshnessAdmissionConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _assert_unchanged(self, payload: dict, before_value: dict, before_ids: dict, before_shape) -> None:
        self.assertEqual(payload, before_value)
        self.assertEqual(_container_identities(payload), before_ids)
        self.assertEqual(_ordered_shape(payload), before_shape)

    def test_strict_digest_rejection_preserves_caller_owned_payload(self):
        produced = self.base._producer(suffix="admission-consumer-rejection-atomicity-strict")
        payload = json.loads(produced[-1].to_json())
        payload["admission_sha256"] = "0" * 64
        before_value = copy.deepcopy(payload)
        before_ids = _container_identities(payload)
        before_shape = _ordered_shape(payload)

        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                self.base._consume(payload, produced)
            self._assert_unchanged(payload, before_value, before_ids, before_shape)

    def test_live_evidence_rejection_preserves_caller_owned_payload(self):
        produced = self.base._producer(suffix="admission-consumer-rejection-atomicity-live")
        evidence_id = produced[10]
        payload = json.loads(produced[-1].to_json())
        before_value = copy.deepcopy(payload)
        before_ids = _container_identities(payload)
        before_shape = _ordered_shape(payload)

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "live validated evidence"):
                self.base._consume(payload, produced)
            self._assert_unchanged(payload, before_value, before_ids, before_shape)


if __name__ == "__main__":
    unittest.main()
