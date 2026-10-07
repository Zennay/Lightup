from __future__ import annotations

import json
import unittest
from unittest import mock

import lightup.future_security_classification_review_request_consumer as consumer_module
import test_future_security_classification_review_request_consumer as consumer_tests


class FutureSecurityClassificationReviewConsumerFailFastOrderingTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityClassificationReviewRequestConsumerTest(
            "test_real_producer_json_is_parsed_and_live_validated_as_one_boundary"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _assert_rejected_before_live_validation(
        self,
        persisted,
        produced,
        *,
        message_pattern: str,
    ):
        messages = []
        with mock.patch.object(
            consumer_module,
            "validate_future_security_classification_review_request",
            side_effect=AssertionError(
                "live classification-review validation must not be reached"
            ),
        ) as live_validator:
            for attempt in range(2):
                with self.subTest(attempt=attempt + 1):
                    with self.assertRaisesRegex(
                        ValueError,
                        message_pattern,
                    ) as raised:
                        self.base._consume(persisted, produced)
                    messages.append(str(raised.exception))
                    live_validator.assert_not_called()

        self.assertEqual(messages[0], messages[1])

    def test_invalid_json_shape_and_type_fail_before_live_validation(self):
        produced = self.base._producer(
            suffix="classification-consumer-failfast-json"
        )
        cases = (
            ("{", "persisted JSON is invalid"),
            (
                '{"schema_version":"a","schema_version":"b"}',
                "duplicate object keys",
            ),
            ("[]", "persisted payload must be an object"),
            (123, "JSON text or object"),
        )

        for persisted, pattern in cases:
            with self.subTest(pattern=pattern):
                self._assert_rejected_before_live_validation(
                    persisted,
                    produced,
                    message_pattern=pattern,
                )

    def test_strict_schema_and_digest_fail_before_live_validation(self):
        produced = self.base._producer(
            suffix="classification-consumer-failfast-strict"
        )
        request = produced[-1]

        schema_invalid = json.loads(request.to_json())
        schema_invalid["unexpected_failfast_probe"] = True

        digest_invalid = json.loads(request.to_json())
        digest = digest_invalid["classification_review_request_sha256"]
        digest_invalid["classification_review_request_sha256"] = (
            ("0" if digest[0] != "0" else "1") + digest[1:]
        )

        cases = (
            (schema_invalid, "payload schema mismatch"),
            (digest_invalid, "digest mismatch"),
        )

        for persisted, pattern in cases:
            with self.subTest(pattern=pattern):
                self._assert_rejected_before_live_validation(
                    persisted,
                    produced,
                    message_pattern=pattern,
                )


if __name__ == "__main__":
    unittest.main()
