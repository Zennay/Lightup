from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

import test_future_security_classification_review_request_consumer as consumer_tests
import lightup.future_security_classification_review_request_consumer as consumer_module


class _PersistedText(str):
    pass


class _PersistedObject(dict):
    pass


class FutureSecurityClassificationReviewRequestConsumerPersistedTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityClassificationReviewRequestConsumerTest(
            "test_real_producer_json_is_parsed_and_live_validated_as_one_boundary"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _producer(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    def test_exact_builtin_persisted_forms_remain_green(self):
        produced = self._producer(
            suffix="classification-review-consumer-persisted-type-controls"
        )
        request = produced[-1]

        from_text = self.base._consume(request.to_json(), produced)
        from_object = self.base._consume(json.loads(request.to_json()), produced)

        self.assertEqual(from_text, request)
        self.assertEqual(from_object, request)

    def test_persisted_json_text_subclass_fails_closed_without_rewrite(self):
        produced = self._producer(
            suffix="classification-review-consumer-persisted-text-subclass"
        )
        persisted = _PersistedText(produced[-1].to_json())
        original = str(persisted)

        with self.assertRaisesRegex(
            ValueError,
            "persisted value must be JSON text or object",
        ):
            self.base._consume(persisted, produced)

        self.assertIs(type(persisted), _PersistedText)
        self.assertEqual(str(persisted), original)

    def test_persisted_mapping_subclass_fails_closed_without_mutation(self):
        produced = self._producer(
            suffix="classification-review-consumer-persisted-object-subclass"
        )
        persisted = _PersistedObject(json.loads(produced[-1].to_json()))
        original = copy.deepcopy(persisted)

        with self.assertRaisesRegex(
            ValueError,
            "persisted value must be JSON text or object",
        ):
            self.base._consume(persisted, produced)

        self.assertIs(type(persisted), _PersistedObject)
        self.assertEqual(persisted, original)

    def test_text_subclass_is_rejected_before_json_decode_dispatch(self):
        produced = self._producer(
            suffix="classification-review-consumer-persisted-text-dispatch"
        )
        persisted = _PersistedText(produced[-1].to_json())

        with mock.patch.object(
            consumer_module.json,
            "loads",
            side_effect=AssertionError("JSON decode must not run for a str subclass"),
        ) as decode:
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must be JSON text or object",
            ):
                self.base._consume(persisted, produced)

        decode.assert_not_called()

    def test_mapping_subclass_is_rejected_before_strict_parser_dispatch(self):
        produced = self._producer(
            suffix="classification-review-consumer-persisted-object-dispatch"
        )
        persisted = _PersistedObject(json.loads(produced[-1].to_json()))

        with mock.patch.object(
            consumer_module,
            "future_security_classification_review_request_from_dict",
            side_effect=AssertionError(
                "strict classification-review parser must not run for a dict subclass"
            ),
        ) as parser:
            with self.assertRaisesRegex(
                ValueError,
                "persisted value must be JSON text or object",
            ):
                self.base._consume(persisted, produced)

        parser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
