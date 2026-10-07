from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_collection_request_consumer as consumer_tests


class _PersistedText(str):
    pass


class _PersistedObject(dict):
    pass


class FutureSecurityEvidenceCollectionConsumerPersistedTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceCollectionRequestConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _producer(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    def test_exact_builtin_persisted_forms_remain_green(self):
        produced = self._producer(suffix="consumer-persisted-type-controls")
        request = produced[-1]

        from_text = self.base._consume(request.to_json(), produced)
        from_object = self.base._consume(json.loads(request.to_json()), produced)

        self.assertEqual(from_text, request)
        self.assertEqual(from_object, request)

    def test_persisted_json_text_subclass_fails_closed_without_rewrite(self):
        produced = self._producer(suffix="consumer-persisted-text-subclass")
        request = produced[-1]
        persisted = _PersistedText(request.to_json())
        original = str(persisted)

        with self.assertRaisesRegex(
            ValueError,
            "persisted value must be JSON text or object",
        ):
            self.base._consume(persisted, produced)

        self.assertIs(type(persisted), _PersistedText)
        self.assertEqual(str(persisted), original)

    def test_persisted_mapping_subclass_fails_closed_without_mutation(self):
        produced = self._producer(suffix="consumer-persisted-object-subclass")
        request = produced[-1]
        persisted = _PersistedObject(json.loads(request.to_json()))
        original = copy.deepcopy(persisted)

        with self.assertRaisesRegex(
            ValueError,
            "persisted value must be JSON text or object",
        ):
            self.base._consume(persisted, produced)

        self.assertIs(type(persisted), _PersistedObject)
        self.assertEqual(persisted, original)


if __name__ == "__main__":
    unittest.main()
