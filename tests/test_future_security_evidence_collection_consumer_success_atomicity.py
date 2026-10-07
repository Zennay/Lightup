from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_collection_request_consumer as consumer_tests


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


class FutureSecurityEvidenceCollectionConsumerSuccessAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceCollectionRequestConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_successful_composed_consumption_preserves_caller_owned_payload(self):
        produced = self.base._producer(suffix="collection-consumer-success-atomicity")
        request = produced[-1]
        payload = json.loads(request.to_json())

        before_value = copy.deepcopy(payload)
        before_ids = _container_identities(payload)
        before_shape = _ordered_shape(payload)

        first = self.base._consume(payload, produced)
        self.assertEqual(first, request)
        self.assertEqual(payload, before_value)
        self.assertEqual(_container_identities(payload), before_ids)
        self.assertEqual(_ordered_shape(payload), before_shape)

        second = self.base._consume(payload, produced)
        self.assertEqual(second, request)
        self.assertEqual(second, first)
        self.assertEqual(payload, before_value)
        self.assertEqual(_container_identities(payload), before_ids)
        self.assertEqual(_ordered_shape(payload), before_shape)


if __name__ == "__main__":
    unittest.main()
